#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <libwebsockets.h>
#include "cemplate.h"

int process_c(char *file, char *out, void *userptr)
{
	printf("'%s' '%s'\n", file, out);
	return cemplate_generate(file, out, userptr);
}

typedef struct
{
	char *public;
} Server;

typedef struct
{
	int count;
} User;

typedef struct
{
	char ext[5];
	char mime[32];
	int (*preprocessor)(char*, char*, void*);
} FileType;

const FileType g_types[] =
{
	{"", "text/plain", NULL},
	{"c", "text/html", process_c},
	{"css", "text/css", NULL},
	{"gif", "image/gif", NULL},
	{"html", "text/html", NULL},
	{"ico", "image/x-icon", NULL},
	{"jpeg", "image/jpg", NULL},
	{"jpg", "image/jpg", NULL},
	{"js", "application/javascript", NULL},
	{"png", "image/png", NULL},
	{0}
};

static const FileType *get_filetype(char *ext, size_t len)
{
    int imin = 0;
    int imax = sizeof(g_types) / sizeof(FileType) - 2;

    /*Binary search.*/
    while (imax >= imin) {
        const int i = (imin + ((imax-imin)/2));
        int c = strncmp(ext, g_types[i].ext, len);
        if (!c) c = '\0' - g_types[i].ext[len];
        if (c == 0) {
            return g_types + i;
        } else if (c > 0) {
            imin = i + 1;
        } else {
            imax = i - 1;
        }
    }
    return 0;
}

static int kek_protocol(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	switch (reason)
	{
	case LWS_CALLBACK_ESTABLISHED:
		printf("connection established\n");
		break;
	case LWS_CALLBACK_RECEIVE:
		{
			unsigned char *buf = (unsigned char*) malloc(LWS_SEND_BUFFER_PRE_PADDING + len +
					LWS_SEND_BUFFER_POST_PADDING);

			int i;

			for (i=0; i < len; i++)
			{
				buf[LWS_SEND_BUFFER_PRE_PADDING + (len - 1) - i ] = ((char *) in)[i];
			}

			printf("received data: %s, replying: %.*s\n", (char *) in, (int) len,
					buf + LWS_SEND_BUFFER_PRE_PADDING);
			lws_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], len, LWS_WRITE_TEXT);
			free(buf);
			break;
		}
	default:
		break;
	}
	return 0;
}

static int callback_http(
		struct lws *wsi,
		enum lws_callback_reasons reason, void *user,
		void *in, size_t len)

{
	if(!wsi)
	{
		return 0;
	}
	Server *server = (Server*)lws_context_user(lws_get_context(wsi));
	static char cwd[1024] = "";
	if(cwd[0] == '\0')
	{
		getcwd(cwd, sizeof(cwd));
	}

	switch (reason)
	{
		case LWS_CALLBACK_CLIENT_WRITEABLE:
			printf("connection established\n");
			break;
		case LWS_CALLBACK_HTTP:
			{
				char *requested_uri = (char *) in;
				printf("requested URI: %s\n", requested_uri);

				if (strcmp(requested_uri, "/") == 0)
				{
					printf("sending global response\n");
					size_t response_len = LWS_SEND_BUFFER_PRE_PADDING + 1000 +
							LWS_SEND_BUFFER_POST_PADDING;
					unsigned char *buf = (unsigned char*) malloc(response_len);
					/* void *universal_response = "Hello, World!"; */

					unsigned char *p = buf + LWS_SEND_BUFFER_PRE_PADDING;
					unsigned char *end = p + 1000 - LWS_SEND_BUFFER_PRE_PADDING;

					lws_add_http_header_status(wsi, 301, &p, end);
					lws_add_http_header_by_token(wsi,
							WSI_TOKEN_HTTP_LOCATION, (unsigned char *)"/index.c", 7, &p, end);
					lws_finalize_http_header(wsi, &p, end);

					lws_write(wsi, buf + LWS_SEND_BUFFER_PRE_PADDING, 1000, LWS_WRITE_HTTP_HEADERS);
					free(buf);
					break;

				} else
				{
					// try to get current working directory
					char *resource_path;

					if (cwd != NULL)
					{
						char resource_path[256] = "";
						sprintf(resource_path, "%s%s", server->public, requested_uri);

						char *extension = strrchr(requested_uri, '.');
						if(extension[0] != '\0')
						{
							extension++;
						}

						const FileType *ft = get_filetype(extension, strlen(extension));
						if(!ft)
						{
							printf("could not find ft=%s\n", extension);
						}
						if(ft->preprocessor)
						{
							char *processed = strdup("templates/tmp/generated.XXXXXX");
							mkstemp(processed);
							ft->preprocessor(resource_path, processed, user);

							lws_serve_http_file(wsi, processed, ft->mime, NULL, 0);
							free(processed);
						}
						else
						{
							lws_serve_http_file(wsi, resource_path, ft->mime, NULL, 0);
						}
					}
				}
				return -1;
				// close connection
				/* lws_close_and_free_session(wsi, LWS_CLOSE_STATUS_NORMAL); */
				break;
			}
		default:
			/* printf("unhandled callback\n"); */
			break;
	}

	return 0;
}

/* list of supported protocols and callbacks */

static struct lws_protocols protocols[] =
{
	/* first protocol must always be HTTP handler */
	{
		"http-only",
		callback_http,
		sizeof(User)
	},
	{
		"kek-protocol",
		kek_protocol,
		sizeof(User)
	},
	{
		NULL, NULL, 0   /* End of list */
	}
};

int main(void)
{
	int port = 80;
	const char *interface = NULL;
	struct lws_context *context;
	// we're not using ssl
	const char *cert_path = NULL;
	const char *key_path = NULL;
	// no special options
	int opts = 0;

	struct lws_context_creation_info info;
	memset(&info, 0, sizeof(info));
	info.port = port;
	info.iface = interface;
	info.protocols = protocols;
	info.extensions = lws_get_internal_extensions();

	Server *server = malloc(sizeof(Server));
	info.user = server;

	server->public = strdup("public");


	info.ssl_cert_filepath = cert_path;
	info.ssl_private_key_filepath = key_path;

	info.gid = -1;
	info.uid = -1;
	info.options = opts;

	context = lws_create_context(&info);

	if (context == NULL)
	{
		fprintf(stderr, "libwebsocket init failed\n");
		return -1;
	}

	printf("starting server...\n");

	while(1)
	{
		lws_service(context, 50);
	}

	lws_context_destroy(context);

	return 0;
}
