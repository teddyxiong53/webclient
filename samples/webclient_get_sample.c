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

#define GET_HEADER_BUFSZ               1024
#define GET_RESP_BUFSZ                 1024

#define GET_LOCAL_URI                  "http://www.rt-thread.com/service/rt-thread.txt"

/* send HTTP GET request by common request interface, it used to receive longer data */
static int webclient_get_comm(const char *uri)
{
    struct webclient_session* session = NULL;
    unsigned char *buffer = NULL;
    int index, ret = 0;
    int bytes_read, resp_status;
    int content_length = -1;

    buffer = (unsigned char *) web_malloc(GET_RESP_BUFSZ);
    if (buffer == NULL)
    {
        printf("no memory for receive buffer.\n");
        ret = -ENOMEM;
        goto __exit;

    }

    /* create webclient session and set header response size */
    session = webclient_session_create(GET_HEADER_BUFSZ);
    if (session == NULL)
    {
        ret = -ENOMEM;
        goto __exit;
    }

    /* send GET request by default header */
    if ((resp_status = webclient_get(session, uri)) != 200)
    {
        printf("webclient GET request failed, response(%d) error.\n", resp_status);
        ret = -1;
        goto __exit;
    }

    printf("webclient get response data: \n");

    content_length = webclient_content_length_get(session);
    if (content_length < 0)
    {
        printf("webclient GET request type is chunked.\n");
        do
        {
            bytes_read = webclient_read(session, buffer, GET_RESP_BUFSZ);
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
    }
    else
    {
        int content_pos = 0;

        do
        {
            bytes_read = webclient_read(session, buffer,
                    content_length - content_pos > GET_RESP_BUFSZ ?
                            GET_RESP_BUFSZ : content_length - content_pos);
            if (bytes_read <= 0)
            {
                break;
            }

            for (index = 0; index < bytes_read; index++)
            {
                printf("%c", buffer[index]);
            }

            content_pos += bytes_read;
        } while (content_pos < content_length);

        printf("\n");
    }

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

/* send HTTP GET request by simplify request interface, it used to received shorter data */
static int webclient_get_smpl(const char *uri)
{
    char *request = NULL;
    int index;

    if (webclient_request(uri, NULL, NULL, (unsigned char **)&request) < 0)
    {
        printf("webclient send get request failed.");
        return -1;
    }

    printf("webclient send get request by simplify request interface.\n");
    printf("webclient get response data: \n");
    for (index = 0; index < strlen(request); index++)
    {
        printf("%c", request[index]);
    }
    printf("\n");

    if (request)
    {
        web_free(request);
    }

    return 0;
}


int webclient_get_test(int argc, char **argv)
{
    char *uri = NULL;

    if (argc == 1)
    {
        uri = web_strdup(GET_LOCAL_URI);
        if(uri == NULL)
        {
            printf("no memory for create get request uri buffer.\n");
            return -ENOMEM;
        }

        webclient_get_comm(uri);
    }
    else if (argc == 2)
    {
        if (strcmp(argv[1], "-s") == 0)
        {
            uri = web_strdup(GET_LOCAL_URI);
            if(uri == NULL)
            {
                printf("no memory for create get request uri buffer.\n");
                return -ENOMEM;
            }

            webclient_get_smpl(uri);
        }
        else
        {
            uri = web_strdup(argv[1]);
            if(uri == NULL)
            {
                printf("no memory for create get request uri buffer.\n");
                return -ENOMEM;
            }
            webclient_get_comm(uri);
        }
    }
    else if(argc == 3 && strcmp(argv[1], "-s") == 0)
    {
        uri = web_strdup(argv[2]);
        if(uri == NULL)
        {
            printf("no memory for create get request uri buffer.\n");
            return -ENOMEM;
        }

        webclient_get_smpl(uri);
    }
    else
    {
        printf("web_get_test [URI]     - webclient GET request test.\n");
        printf("web_get_test -s [URI]  - webclient simplify GET request test.\n");
        return -1;
    }

    if (uri)
    {
        web_free(uri);
    }

    return 0;
}
