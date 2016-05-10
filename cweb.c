#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <libwebsockets.h>
#include <jansson.h>
#include "cemplate.h"
#include "cweb.h"


typedef struct
{
	char name[128];
	event_callback_t cb;
} cweb_event_t;

typedef struct
{
	unsigned char *from;
	unsigned char *to;
} cweb_redirect_t;

typedef struct cweb_t
{
	char public[256];
	struct lws_context_creation_info info;
	void *userptr;
	struct lws_protocols protocols[64];

	cweb_event_t *events;
	unsigned int events_num;

	cweb_redirect_t *redirects;
	size_t redirects_num;

	cweb_room_t *rooms;
	size_t rooms_num;
} cweb_t;

typedef struct cweb_socket_t
{
	void *userptr;
	cweb_t *server;
	struct lws *wsi;

	cweb_room_t *rooms[32];

	cweb_event_t *events;
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
		{"mp3", "audio/mpeg", NULL},
		{"png", "image/png", NULL},
		{"ttf", "application/octet-stream", NULL},
		{"wav", "audio/wav", NULL},
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

static void dump_handshake_info(struct lws_tokens *lwst)
{
	int n;
	static const char *token_names[] = {
		/*[WSI_TOKEN_GET_URI]		=*/ "GET URI",
		/*[WSI_TOKEN_HOST]		=*/ "Host",
		/*[WSI_TOKEN_CONNECTION]	=*/ "Connection",
		/*[WSI_TOKEN_KEY1]		=*/ "key 1",
		/*[WSI_TOKEN_KEY2]		=*/ "key 2",
		/*[WSI_TOKEN_PROTOCOL]		=*/ "Protocol",
		/*[WSI_TOKEN_UPGRADE]		=*/ "Upgrade",
		/*[WSI_TOKEN_ORIGIN]		=*/ "Origin",
		/*[WSI_TOKEN_DRAFT]		=*/ "Draft",
		/*[WSI_TOKEN_CHALLENGE]		=*/ "Challenge",

		/* new for 04 */
		/*[WSI_TOKEN_KEY]		=*/ "Key",
		/*[WSI_TOKEN_VERSION]		=*/ "Version",
		/*[WSI_TOKEN_SWORIGIN]		=*/ "Sworigin",

		/* new for 05 */
		/*[WSI_TOKEN_EXTENSIONS]	=*/ "Extensions",

		/* client receives these */
		/*[WSI_TOKEN_ACCEPT]		=*/ "Accept",
		/*[WSI_TOKEN_NONCE]		=*/ "Nonce",
		/*[WSI_TOKEN_HTTP]		=*/ "Http",
	};
	
	for (n = 0; n < WSI_TOKEN_COUNT; n++) {
		if (lwst[n].token == NULL)
			continue;

		fprintf(stderr, "    %s = %s\n", token_names[n], lwst[n].token);
	}
}
const static event_callback_t cweb_socket_get_event(const cweb_socket_t *self,
		const char *name)
{
	const cweb_t *server = self->server;
	int i;

	for(i = 0; i < server->events_num; i++)
	{
		if(!strcmp(name, server->events[i].name))
		{
			return server->events[i].cb;
		}
	}
	for(i = 0; i < self->events_num; i++)
	{
		if(!strcmp(name, self->events[i].name))
		{
			return self->events[i].cb;
		}
	}
	return NULL;
}

cweb_t *cweb_socket_get_server(cweb_socket_t *self)
{
	return self->server;
}

void cweb_socket_send(cweb_socket_t *self, const char *message, size_t len)
{
	if(len)
	{
		unsigned char *buf = malloc(LWS_SEND_BUFFER_PRE_PADDING + len +
				LWS_SEND_BUFFER_POST_PADDING);
		strcpy(buf + LWS_SEND_BUFFER_PRE_PADDING, message);

		lws_write(self->wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], len, LWS_WRITE_TEXT);

		free(buf);
	}
}

static char *generate_emit_message(const char *emit_name, json_t *data)
{
	json_t *info = json_object();
	json_t *jname = json_string(emit_name);
	json_object_set(info, "event", jname);

	if(data != NULL)
	{
		json_object_set(info, "data", data);
	}

	char *message = json_dumps(info, 0);

	json_decref(jname);
	json_decref(info);

	return message;
}

void cweb_socket_emit(cweb_socket_t *self, const char *event, json_t *data)
{
	char *message = generate_emit_message(event, data);
	cweb_socket_send(self, message, strlen(message));
	free(message);
}

cweb_room_t *cweb_get_room(cweb_t *self, const char *room)
{
	int i;
	for(i = 0; i < self->rooms_num; i++)
	{
		if(!strcmp(room, self->rooms[i].name))
		{
			return &self->rooms[i];
		}
	}
	return NULL;
}

cweb_room_t *cweb_socket_get_room(cweb_socket_t *self, const char *room)
{
	return cweb_get_room(cweb_socket_get_server(self), room);
}

void cweb_to_room_send(cweb_t *self, const char *room_name,
		const char *message, size_t len, cweb_socket_t *except)
{
	int i;
	cweb_room_t *room = cweb_get_room(self, room_name);
	if(!room) return;

	for(i = 0; i < room->sockets_num; i++)
	{
		if(room->sockets[i] && room->sockets[i]->wsi && room->sockets[i] != except)
		{
			cweb_socket_send(room->sockets[i], message, len);
		}
	}
}

void cweb_to_room_emit(cweb_t *self, const char *room_name,
		const char *event, json_t *data, cweb_socket_t *except)
{
	char *message = generate_emit_message(event, data);
	size_t len = strlen(message);

	cweb_to_room_send(self, room_name, message, len, except);

	free(message);
}

void cweb_socket_to_room_emit(cweb_socket_t *self, const char *room,
		const char *event, json_t *data, cweb_socket_t *except)
{
	cweb_to_room_emit(cweb_socket_get_server(self), room, event, data, except);
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
		socket->wsi = wsi;
		cb = cweb_socket_get_event(socket, "connected");
		if(cb)
		{
			cb(socket, NULL);
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		json = json_loads(in, 0, &error);
		event = json_object_get(json, "event");
		data = json_object_get(json, "data");

		cb = cweb_socket_get_event(socket, json_string_value(event));
		if(cb)
		{
			cb(socket, data);
		}
		json_decref(event);
		json_decref(data);
		json_decref(json);
		break;

	case LWS_CALLBACK_CLOSED:
		socket->wsi = NULL;
		cb = cweb_socket_get_event(socket, "disconnected");

		for(cweb_room_t **room_iter = socket->rooms; *room_iter; room_iter++)
		{
			for(int i = 0; i < (*room_iter)->sockets_num; i++)
			{
				cweb_socket_t **soc = &(*room_iter)->sockets[i];
				if((*soc) == socket)
				{
					(*soc) = NULL;
				}
			}
		}

		if(cb)
		{
			cb(socket, NULL);
		}
		break;

	case LWS_CALLBACK_PROTOCOL_INIT:
		printf("Protocol started successfully.\n");
		break;
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		/* you could return non-zero here and kill the connection */
		break;
	default:
		printf("REASON: %d\n", reason);
		break;
	}
	return 0;
}

static cweb_redirect_t *cweb_get_redirect(const cweb_t *self,
		const unsigned char *from)
{
	int i;
	for(i = 0; i < self->redirects_num; i++)
	{
		if(!strcmp(from, self->redirects[i].from))
		{
			return &self->redirects[i];
		}
	}
	return NULL;
}

static int lws_serve_http_string(struct lws *wsi,
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
		if(!getcwd(cwd, sizeof(cwd)))
		{
			fprintf(stderr, "Could not get working directory!");
		}
	}

	switch (reason)
	{
		case LWS_CALLBACK_CLIENT_WRITEABLE:
			printf("connection established\n");
			break;
		case LWS_CALLBACK_HTTP:
			{
				char *resource_path;
				int cweb_resources = 0;
				char *requested_uri = (char *) in;
				/* printf("requested URI: %s\n", requested_uri); */

				cweb_redirect_t *redir = cweb_get_redirect(server, requested_uri);
				if(redir)
				{
					printf("redirecting from %s to %s\n", redir->from, redir->to);
					size_t response_len = LWS_SEND_BUFFER_PRE_PADDING + 1000 +
						LWS_SEND_BUFFER_POST_PADDING;
					unsigned char *buf = (unsigned char*) malloc(response_len);
					/* void *universal_response = "Hello, World!"; */

					unsigned char *p = buf + LWS_SEND_BUFFER_PRE_PADDING;
					unsigned char *end = p + 1000;

					lws_add_http_header_status(wsi, 301, &p, end);
					lws_add_http_header_by_token(wsi,
							WSI_TOKEN_HTTP_LOCATION,
							redir->to, strlen(redir->to), &p, end);

					lws_finalize_http_header(wsi, &p, end);

					lws_write(wsi, buf + LWS_SEND_BUFFER_PRE_PADDING, 1000, LWS_WRITE_HTTP_HEADERS);
					free(buf);
					break;
				}

				if(strncmp(requested_uri, "/cweb/", sizeof("/cweb/") - 1) == 0)
				{
					requested_uri += sizeof("/cweb/") - 2;
					cweb_resources = 1;
				}

				if (cwd != NULL)
				{
					char resource_path[256] = "";
					sprintf(resource_path, "%s%s", cweb_resources?
							"/usr/share/cweb/resources":server->public,
							requested_uri);

					char *extension = strrchr(requested_uri, '.');

					if(extension && extension[0] != '\0')
					{
						extension++;
					}

					const file_type_t *ft = get_filetype(extension);
					if(ft && ft->preprocessor)
					{
						char *buffer = NULL;
						int len = ft->preprocessor(resource_path, &buffer, cwebuser);
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

static void cweb_add_protocol(cweb_t *self, const char *name, void *
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
	self->info.extensions = NULL;

	self->redirects = NULL;
	self->redirects_num = 0;

	self->rooms = NULL;
	self->rooms_num = 0;

	self->info.user = self;

	self->info.ssl_cert_filepath = NULL;
	self->info.ssl_private_key_filepath = NULL;

	self->info.gid = -1;
	self->info.uid = -1;
	self->info.options = 0;
	return self;
}

void *cweb_socket_get_user_ptr(cweb_socket_t *self)
{
	return self->userptr;
}

void cweb_socket_set_user_ptr(cweb_socket_t *self, void *userptr)
{
	self->userptr = userptr;
}

void *cweb_get_user_ptr(cweb_t *self)
{
	return self->userptr;
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

	while(1)
	{
		lws_service(context, 50);
	}

	lws_context_destroy(context);

	free(self->events);
	free(self->rooms);
	int i;
	for(i = 0; i < self->redirects_num; i++)
	{
		free(self->redirects[i].from);
		free(self->redirects[i].to);
	}
	free(self->redirects);

	return 0;
}

void cweb_sockets_on(cweb_t *self, const char *event, event_callback_t cb)
{
	unsigned int l = self->events_num + 1;
	self->events = realloc(self->events, (sizeof *self->events) * l);
	cweb_event_t *ev = &self->events[l - 1];
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
	self->events = realloc(self->events, (sizeof *self->events) * l);
	cweb_event_t *ev = &self->events[l - 1];
	ev->cb = cb;
	strcpy(ev->name, event);
	self->events_num = l;
}

void cweb_redirect(cweb_t *self, const char *from, const char *to)
{
	cweb_redirect_t *redir = cweb_get_redirect(self, from);
	if(redir == NULL)
	{
		/* printf("Redirect %s does not exist, adding (%lu)\n", from, self->redirects_num); */
		size_t l = self->redirects_num + 1;
		self->redirects = realloc(self->redirects, (sizeof *self->redirects) * l);
		redir = &self->redirects[l - 1];
		self->redirects_num = l;
	}
	redir->from = (unsigned char*)strdup(from);
	redir->to = (unsigned char*)strdup(to);
}

static cweb_room_t *cweb_add_room(cweb_t *self, const char *room_name)
{
	size_t l = self->rooms_num + 1;
	self->rooms = realloc(self->rooms, l * sizeof(*self->rooms));

	cweb_room_t *room = &self->rooms[l - 1];
	strcpy(room->name, room_name);
	room->sockets = NULL;
	room->sockets_num = 0;

	self->rooms_num = l;

	return room;
}
 
void cweb_socket_join(cweb_socket_t *self, const char *room_name)
{
	int i;
	cweb_t *server = cweb_socket_get_server(self);
	cweb_room_t *room = cweb_get_room(server, room_name);
	if(!room)
	{
		room = cweb_add_room(server, room_name);
	}

	cweb_socket_t **room_free_socket = NULL;
	for(i = 0; i < room->sockets_num; i++)
	{
		if(room->sockets[i] == NULL)
		{
			room_free_socket = &room->sockets[i];
			break;
		}
	}

	if(!room_free_socket)
	{
		size_t l = room->sockets_num + 1;
		room->sockets = realloc(room->sockets, l * sizeof(*room->sockets));
		room_free_socket = &room->sockets[l - 1];
		room->sockets_num = l;
	}

	(*room_free_socket) = self;

	cweb_room_t **room_iter;
	for(room_iter = self->rooms; *(room_iter + 1); room_iter++);
	(*room_iter) = room;
}

