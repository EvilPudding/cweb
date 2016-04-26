#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <libwebsockets.h>
#include <jansson.h>
#include "cemplate.h"


typedef struct cweb_socket_t cweb_socket_t;
typedef struct cweb_t cweb_t;

typedef void(*event_callback_t)(cweb_socket_t *self, cweb_t *server, const
		json_t *data);

typedef struct
{
	char name[128];
	event_callback_t cb;
} cweb_event_t;

typedef struct cweb_t
{
	char public[256];
	struct lws_context_creation_info info;
	void *userptr;
	struct lws_protocols protocols[64];

	cweb_event_t **events;
	unsigned int events_num;
} cweb_t;

typedef struct cweb_socket_t
{
	int count;
	void *userptr;
	cweb_t *server;

	cweb_event_t **events;
	unsigned int events_num;
} cweb_socket_t;

typedef struct
{
	char ext[5];
	char mime[32];
	size_t (*preprocessor)(char*, char**, void*);
} file_type_t;

size_t process_c(char *file, char **out, void *userptr)
{
	return cemplate_generate_to_string(file, out, userptr);
}

static const file_type_t *get_filetype(char *ext)
{
	static const file_type_t types[] =
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
	}; /* types must be sorted by ext */

	int imin = 0;
	int imax = sizeof(types) / sizeof(file_type_t) - 2;
	if(!ext) return &types[0];
	size_t len = strlen(ext);
	if(!len) return &types[0];
	while (imax >= imin)
	{
		const int i = (imin + ((imax-imin)/2));
		int c = strncmp(ext, types[i].ext, len);
		if (!c) c = '\0' - types[i].ext[len];
		if (c == 0)
		{
			return types + i;
		}
		else if (c > 0)
		{
			imin = i + 1;
		}
		else
		{
			imax = i - 1;
		}
	}
	return 0;
}

const static event_callback_t cweb_socket_get_event(const cweb_socket_t *self,
		const char *name)
{
	const cweb_t *server = self->server;
	int i;

	for(i = 0; i < server->events_num; i++)
	{
		if(!strcmp(name, server->events[i]->name))
		{
			return server->events[i]->cb;
		}
	}
	for(i = 0; i < self->events_num; i++)
	{
		if(!strcmp(name, self->events[i]->name))
		{
			return self->events[i]->cb;
		}
	}
	return NULL;
}

static int cweb_websocket_protocol(
		struct lws *wsi,
		enum lws_callback_reasons reason,
		void *cwebptr, void *in, size_t len)
{
	cweb_socket_t *socket = cwebptr;
	cweb_t *server = lws_context_user(lws_get_context(wsi));
	event_callback_t cb = NULL;

	json_error_t error;
	json_t *json, *event, *data;
	switch(reason)
	{

	case LWS_CALLBACK_ESTABLISHED:
		socket->server = server;
		cb = cweb_socket_get_event(socket, "connected");
		if(cb)
		{
			cb(socket, server, NULL);
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		json = json_loads(in, 0, &error);
		event = json_object_get(json, "event");
		data = json_object_get(json, "data");

		cb = cweb_socket_get_event(socket, json_string_value(event));
		if(cb)
		{
			cb(socket, server, data);
		}
		json_decref(event);
		json_decref(data);
		json_decref(json);
		break;

	case LWS_CALLBACK_CLOSED:
		cb = cweb_socket_get_event(socket, "disconnected");
		if(cb)
		{
			cb(socket, server, NULL);
		}
		break;

	default:
		printf("REASON: %d\n", reason);
		break;
	}
	return 0;
}

LWS_VISIBLE int lws_serve_http_string(struct lws *wsi,
				    const char *string,
				    const size_t stringlen,
				    const char *content_type,
				    const char *other_headers,
				    int other_headers_len)
{
	size_t response_len = LWS_SEND_BUFFER_PRE_PADDING + stringlen +
		LWS_SEND_BUFFER_POST_PADDING;

	unsigned char *buffer = malloc(response_len);
	unsigned char *response = buffer + LWS_SEND_BUFFER_PRE_PADDING;
	unsigned char *p = response;
	unsigned char *end = p + stringlen;

	int ret = 0;

	if (lws_add_http_header_status(wsi, 200, &p, end))
		return -1;
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SERVER,
					 (unsigned char *)"libwebsockets", 13,
					 &p, end))
		return -1;
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					 (unsigned char *)content_type,
					 strlen(content_type), &p, end))
		return -1;
	if (lws_add_http_header_content_length(wsi, stringlen, &p, end))
		return -1;

	if (other_headers) {
		if ((end - p) < other_headers_len)
			return -1;
		memcpy(p, other_headers, other_headers_len);
		p += other_headers_len;
	}

	if (lws_finalize_http_header(wsi, &p, end))
		return -1;

	strcpy(response, string);

	ret = lws_write(wsi, response, stringlen, LWS_WRITE_HTTP_HEADERS);
	/* ret = lws_write(wsi, response, stringlen, LWS_WRITE_TEXT); */
	

	free(buffer);

	return ret;
}

static int cweb_http_protocol(
		struct lws *wsi,
		enum lws_callback_reasons reason, void *cwebuser,
		void *in, size_t len)

{
	if(!wsi)
	{
		return 0;
	}
	cweb_t *server = lws_context_user(lws_get_context(wsi));

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
					unsigned char *end = p + 1000;

					lws_add_http_header_status(wsi, 301, &p, end);
					lws_add_http_header_by_token(wsi,
							WSI_TOKEN_HTTP_LOCATION, (unsigned char *)"/index.c", 8, &p, end);
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

						if(extension && extension[0] != '\0')
						{
							extension++;
						}

						const file_type_t *ft = get_filetype(extension);
						if(!ft)
						{
							printf("could not find ft=%s\n", extension);
						}
						if(ft->preprocessor)
						{
							char *buffer = NULL;
							int len = ft->preprocessor(resource_path, &buffer, NULL);
							if(len == -1)
							{
								lws_serve_http_file(wsi, "missing", ft->mime, NULL, 0);
							}
							else
							{
								lws_serve_http_string(wsi, buffer, (size_t)len, ft->mime, NULL, 0);
								free(buffer);
							}
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

static void cweb_add_protocol(cweb_t *self, const char *name, callback_function
		callback, size_t per_session_data_size)
{
	struct lws_protocols *protocol;
	for(protocol = self->protocols; protocol->name; protocol++);

	protocol->name = strdup(name);
	protocol->callback = callback;
	protocol->per_session_data_size = per_session_data_size;
}

cweb_t *cweb_new(const int port)
{
	cweb_t *self = calloc(1, sizeof(*self));

	cweb_add_protocol(self, "http-only", cweb_http_protocol, 0);

	memset(&self->info, 0, sizeof(self->info));
	self->info.port = port;

	self->info.iface = NULL;
	self->info.protocols = self->protocols;
	self->info.extensions = lws_get_internal_extensions();

	self->info.user = self;

	self->info.ssl_cert_filepath = NULL;
	self->info.ssl_private_key_filepath = NULL;

	self->info.gid = -1;
	self->info.uid = -1;
	self->info.options = 0;
	return self;
}

void cweb_socket_set_user_ptr(cweb_socket_t *self, void *userptr)
{
	self->userptr = userptr;
}

void cweb_set_user_ptr(cweb_t *self, void *userptr)
{
	self->userptr = userptr;
}

void cweb_set_public(cweb_t *self, const char *dir)
{
	strcpy(self->public, dir);
}

int cweb_run(cweb_t *self)
{
	struct lws_context *context;

	context = lws_create_context(&self->info);

	if(!context)
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

void cweb_sockets_on(cweb_t *self, const char *event, event_callback_t cb)
{
	unsigned int l = self->events_num + 1;
	self->events = realloc(self->events, sizeof(*self->events) * l);
	cweb_event_t *ev = self->events[l - 1] = malloc(sizeof(*ev));
	ev->cb = cb;
	strcpy(ev->name, event);
	self->events_num = l;

	if(!strcmp(event, "connected"))
	{
		cweb_add_protocol(self, "cwebsockets", cweb_websocket_protocol, sizeof(cweb_socket_t));
	}
}

void cweb_socket_on(cweb_socket_t *self, const char *event, event_callback_t cb)
{
	unsigned int l = self->events_num + 1;
	self->events = realloc(self->events, sizeof(*self->events) * l);
	cweb_event_t *ev = self->events[l - 1] = malloc(sizeof(*ev));
	ev->cb = cb;
	strcpy(ev->name, event);
	self->events_num = l;
}

/* USER SPACE */

typedef struct { int KEK; } TOP;

void socket_message(cweb_socket_t *socket, cweb_t *server, const json_t *data)
{
	printf("Received message: '%s'\n", json_string_value(data));
}

void sockets_connected(cweb_socket_t *socket, cweb_t *server, const json_t *data)
{
	TOP *top = malloc(sizeof(TOP));

	cweb_socket_on(socket, "message", socket_message);

	cweb_socket_set_user_ptr(socket, top);
}

int main(int argc, char **argv)
{
	int port = 80;
	cweb_t *server = cweb_new(80);
	cweb_set_public(server, "public");

	cweb_sockets_on(server, "connected", sockets_connected);

	cweb_run(server);
}
