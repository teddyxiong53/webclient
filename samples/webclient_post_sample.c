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

#define POST_RESP_BUFSZ                1024
#define POST_HEADER_BUFSZ              1024

#define POST_LOCAL_URI                 "http://www.rt-thread.com/service/echo"

const char *post_data = "RT-Thread is an open source IoT operating system from China!";

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
    webclient_header_fields_add(session, "Content-Type: application/octet-stream\r\n");

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
        uri = web_strdup(POST_LOCAL_URI);
        if(uri == NULL)
        {
            printf("no memory for create post request uri buffer.\n");
            return -ENOMEM;
        }

        webclient_post_comm(uri, post_data);
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


