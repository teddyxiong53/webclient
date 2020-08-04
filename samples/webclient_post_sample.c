/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018-08-03    chenyong      the first version
 */

#include <webclient.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <stddef.h>
#include "cJSON.h"

#include "mylog.h"

#define POST_RESP_BUFSZ                1024
#define POST_HEADER_BUFSZ              1024

// #define POST_LOCAL_URI                 "http://www.rt-thread.com/service/echo"
#define POST_LOCAL_URI         "http://smartdevice.ai.tuling123.com/speech/chat"

const char *post_data = "RT-Thread is an open source IoT operating system from China!";

static int webclient_post_comm(const char *uri, const char *post_data);

struct uuid_type {
	char buf[33];
};



void gen_uuid_r(struct uuid_type* uuid)
{
	srand(1);
	const char *c = "89ab";

	char *p = uuid->buf;
	int n;
	for (n = 0; n < 16; ++n)
	{
		int b = rand() % 255;
		switch (n)
		{
		case 6:
			sprintf(p, "4%x", b % 15);
			break;
		case 8:
			sprintf(p, "%c%x", c[rand() % strlen(c)], b % 15);
			break;
		default:
			sprintf(p, "%02x", b);
			break;
		}

		p += 2;
#if 0 //这样会有4个 - 符号。我不需要。
		switch (n)
		{
		case 3:
		case 5:
		case 7:
		case 9:
			*p++ = '-';
			break;
		}
#endif
	}
	*p = 0;
}

#define NEWLINE "\r\n"
#define BOUND_LEN (33+2+2) //33是uuid（已经包含\0了），4个字节的----开头，4个字节的----结尾
static char g_uuid[33];
static char g_begin_boundary[BOUND_LEN];
static char g_end_boundary[BOUND_LEN];
#define DEVICE_SN "ai20200729000001"

#define API_KEY  "a1d84bcae1c848f892bcfe0effe9d5e8"
//这个现在需要post音频数据，所以需要放大一些。
#define MAX_POST_LEN  4096
#define MAX_HEADER_LEN 1024
#define MAX_OUTPUT_LEN 1024




static char *gen_begin_boundary()
{
	strcpy(g_begin_boundary, "--");
	strcat(g_begin_boundary, g_uuid);
	// mylogd("g_begin_boundary:%s", g_begin_boundary);
	return g_begin_boundary;
}

static char *gen_end_boundary()
{
	strcpy(g_end_boundary, "--");
	strcat(g_end_boundary, g_uuid);
	strcat(g_end_boundary, "--");
	return g_end_boundary;
}

static void update_uuid()
{
	struct uuid_type uuid;
	gen_uuid_r(&uuid);
	strcpy(g_uuid, uuid.buf);
	// mylogd("----------------uuid:%s", g_uuid);
}

/*
直接返回字符串。
再外面拿到字符串之后，把字符串释放掉。
speech为音频文件，当为主动交互请求（type=1）或者提示语请求（type=2）时，该字段无效。
*/
char *gen_parameters_json()
{
	static int i = 1;
	cJSON *root = cJSON_CreateObject();
	cJSON *ak = cJSON_CreateString(API_KEY);
	cJSON *uid = cJSON_CreateString("56DF1DFE12AEE68411FFEB2B9D00AB37");
	cJSON *token = cJSON_CreateString("2af62825b9cd49568cc55a6256a86239");
	cJSON *asr = cJSON_CreateNumber(4);//opus
	cJSON *tts = cJSON_CreateNumber(3);//mp3 16bit
	cJSON *tone = cJSON_CreateNumber(20);//20到22。发声人id
	cJSON *flag = cJSON_CreateNumber(3);//3表示同时asr和tts文本信息，就用这个。
	cJSON *realTime = cJSON_CreateNumber(1);//按片段上传音频，而不是用文件的方式。
	cJSON *index = cJSON_CreateNumber(i++);//音频片段的index，从1开始，最后一片为负数，例如1,2,3，-4这样。
	struct uuid_type uuid;
	gen_uuid_r(&uuid);
	cJSON *identify = cJSON_CreateString(uuid.buf);//这个要是可以唯一标识一次交互，32个字符，只能是数字和小写字母。那就用uuid。uuid要改成可以重入的。
	cJSON *type = cJSON_CreateNumber(2);//0：智能聊天。1：主动交互。2：开机提示语。4：绘本模式（需要商务沟通）。5：文本输入。

	cJSON_AddItemToObject(root, "ak", ak);
	cJSON_AddItemToObject(root, "uid", uid);
	cJSON_AddItemToObject(root, "token", token);
	cJSON_AddItemToObject(root, "asr", asr);
	cJSON_AddItemToObject(root, "tts", tts);
	cJSON_AddItemToObject(root, "tone", tone);
	cJSON_AddItemToObject(root, "flag", flag);
	cJSON_AddItemToObject(root, "realTime", realTime);
	cJSON_AddItemToObject(root, "identify", identify);
	cJSON_AddItemToObject(root, "type", type);
	char *json = cJSON_Print(root);
	return json;
}

static char *_send_event()
{
	char *audio_data = NULL;
	int  audio_size = 0;
	static volatile int flag = 0;

	while (flag) {
		usleep(100);
	}
	flag = 1;//这个是为了避免同时多个函数同时执行。
	char *header = NULL;
	//如何构造header呢？
	//就分配一个buf，然后用strcat来拼。
	header = (char *)malloc(MAX_HEADER_LEN);
	if (!header) {
		myloge("malloc fail");
		goto end;
	}
	memset(header, 0, MAX_HEADER_LEN);
	update_uuid();//每一次post，都只需要更新一次uuid。


				  //下面的属于body部分。
	char *input = malloc(MAX_POST_LEN);
	if (!input) {
		myloge("malloc fail");
		goto end;
	}
	//memset(input, 0, MAX_POST_LEN);//尽量减少不必要的清空操作。
	//分隔符，我就用----uuid来做开头。----uuid----来做结尾。
	//Content-Disposition: form-data; name="parameters"

	strcpy(input, gen_begin_boundary());//因为input没有被清零，所以第一个需要strcpy来赋值。
	strcat(input, NEWLINE);
	strcat(input, "Content-Disposition: form-data; name=\"parameters\"");
	strcat(input, NEWLINE);
	strcat(input, NEWLINE);//多一个空行
						   //然后把parameter的json放进来。

    #if 1
	char *parameters = gen_parameters_json();
	strcat(input, parameters);
	free(parameters);//可以释放这个了。
	strcat(input, NEWLINE);
	int text_len = (strlen(input));
	mylogd("input text_len without speech:%d", text_len);
	//然后是speech数据，这个是可以没有的。
	if (audio_size > 0)
	{
		strcat(input, gen_begin_boundary());
		strcat(input, NEWLINE);
		strcat(input, "Content-Disposition: form-data; name=\"speech\"");
		strcat(input, NEWLINE);
		strcat(input, "Content-Type: application/octet-stream");
		strcat(input, NEWLINE);
		strcat(input, NEWLINE);//这里多一个空行
		text_len = (strlen(input) + 1);//这里更新text_len
									   //然后就是二进制数据。
		memcpy(input + text_len, audio_data, audio_size);
	}
    #endif
	//然后是boundary结束
	char buf[100] = { 0 };
	strcpy(buf, gen_end_boundary());
	strcat(buf, NEWLINE);
	int end_boundary_size = strlen(buf);
	mylogd("input end_boundary_size:%d", end_boundary_size);
	//把尾部拷贝到input缓冲区的最后。
	if (audio_size > 0) {
		//现在这个还不对。
		memcpy(input + text_len + audio_size, buf, end_boundary_size);
	}
	else {
		strcat(input, buf);
	}


	int ilen = text_len + audio_size + end_boundary_size;
	mylogd("input ilen:%d", ilen);
	char *output = malloc(MAX_OUTPUT_LEN);
	if (!output) {
		myloge("malloc fail");
		goto end;
	}
	memset(output, 0, MAX_OUTPUT_LEN);
	int olen = 0;
#if 0
	printf("-------------header--------------\n");
	printf("%s\n", header);
	printf("----------------------------------\n");
	printf("-------------body--------------\n");
	printf("%s\n", input);
	printf("----------------------------------\n");
#endif
	webclient_post_comm("http://smartdevice.ai.tuling123.com/speech/chat", input );

	//最后释放资源
end:
	if (header) {
		free(header);
	}
	if (input) {
		free(input);
	}
	if (output) {
		free(output);
	}
	flag = 0;
}


/* send HTTP POST request by common request interface, it used to receive longer data */
static int webclient_post_comm(const char *uri, const char *post_data)
{
    struct webclient_session* session = NULL;
    unsigned char *buffer = NULL;
    int index, ret = 0;
    int bytes_read, resp_status;

    buffer = (unsigned char *) web_malloc(POST_RESP_BUFSZ);
    if (buffer == NULL)
    {
        printf("no memory for receive response buffer.\n");
        ret = -ENOMEM;
        goto __exit;
    }

    /* create webclient session and set header response size */
    session = webclient_session_create(POST_HEADER_BUFSZ);
    if (session == NULL)
    {
        ret = -ENOMEM;
        goto __exit;
    }

    /* build header for upload */
    webclient_header_fields_add(session, "Content-Length: %d\r\n", strlen(post_data));
    webclient_header_fields_add(session, "Content-Type: multipart/form-data; boundary=%s\r\n", g_uuid);

    /* send POST request by default header */
    if ((resp_status = webclient_post(session, uri, post_data)) != 200)
    {
        printf("webclient POST request failed, response(%d) error.\n", resp_status);
        ret = -1;
        goto __exit;
    }

    printf("webclient post response data: \n");
    do
    {
        bytes_read = webclient_read(session, buffer, POST_RESP_BUFSZ);
        if (bytes_read <= 0)
        {
            break;
        }

        for (index = 0; index < bytes_read; index++)
        {
            printf("%c", buffer[index]);
        }
    } while (1);

    printf("\n");

__exit:
    if (session)
    {
        webclient_close(session);
    }

    if (buffer)
    {
        web_free(buffer);
    }

    return ret;
}

/* send HTTP POST request by simplify request interface, it used to received shorter data */
static int webclient_post_smpl(const char *uri, const char *post_data)
{
    char *request = NULL, *header = NULL;
    int index;

    webclient_request_header_add(&header, "Content-Length: %d\r\n", strlen(post_data));
    webclient_request_header_add(&header, "Content-Type: application/octet-stream\r\n");

    if (webclient_request(uri, (const char *)header, post_data, (unsigned char **)&request) < 0)
    {
        printf("webclient send post request failed.");
        web_free(header);
        return -1;
    }

    printf("webclient send post request by simplify request interface.\n");
    printf("webclient post response data: \n");
    for (index = 0; index < strlen(request); index++)
    {
        printf("%c", request[index]);
    }
    printf("\n");

    if (header)
    {
        web_free(header);
    }

    if (request)
    {
        web_free(request);
    }

    return 0;
}


int webclient_post_test(int argc, char **argv)
{
    char *uri = NULL;

    if (argc == 1)
    {
        #if 0
        uri = web_strdup(POST_LOCAL_URI);
        if(uri == NULL)
        {
            printf("no memory for create post request uri buffer.\n");
            return -ENOMEM;
        }
        webclient_post_comm(uri, post_data);
        #else
        _send_event();
        #endif
    }
    else if (argc == 2)
    {
        if (strcmp(argv[1], "-s") == 0)
        {
            uri = web_strdup(POST_LOCAL_URI);
            if(uri == NULL)
            {
                printf("no memory for create post request uri buffer.\n");
                return -ENOMEM;
            }

            webclient_post_smpl(uri, post_data);
        }
        else
        {
            uri = web_strdup(argv[1]);
            if(uri == NULL)
            {
                printf("no memory for create post request uri buffer.\n");
                return -ENOMEM;
            }
            webclient_post_comm(uri, post_data);
        }
    }
    else if(argc == 3 && strcmp(argv[1], "-s") == 0)
    {
        uri = web_strdup(argv[2]);
        if(uri == NULL)
        {
            printf("no memory for create post request uri buffer.\n");
            return -ENOMEM;
        }

        webclient_post_smpl(uri, post_data);
    }
    else
    {
        printf("web_post_test [uri]     - webclient post request test.\n");
        printf("web_post_test -s [uri]  - webclient simplify post request test.\n");
        return -1;
    }

    if (uri)
    {
        web_free(uri);
    }

    return 0;
}


