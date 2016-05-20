#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <libwebsockets.h>
#include <jansson.h>
#include "cemplate.h"
#include "cweb.h"
#include <fcntl.h> 

typedef struct
{
	char name[128];
	event_callback_t cb;
	int response_id;
} cweb_event_t;

typedef struct
{
	unsigned char *from;
	unsigned char *to;
} cweb_redirect_t;

typedef struct
{
	int id;
	cweb_socket_response_t cb;
} cweb_response_t;

typedef struct cweb_t
{
	char public[256];
	struct lws_context_creation_info info;
	void *userptr;
	struct lws_protocols protocols[64];

	cweb_event_t *events;
	unsigned int events_num;

	size_t redirects_num;
	cweb_redirect_t *redirects;

	size_t rooms_num;
	cweb_room_t **rooms;

} cweb_t;

typedef struct cweb_socket_t
{
	void *userptr;
	cweb_t *server;
	struct lws *wsi;
	int ms_id;

	cweb_room_t *rooms[32];

	size_t responses_num;
	cweb_response_t *responses;

	cweb_event_t *events;
	unsigned int events_num;

	int pipe[2];
	int httpipe[2];
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
		if(!c) c = '\0' - types[i].ext[len];
		if(c == 0)
		{
			return types + i;
		}
		else if(c > 0)
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

static void cweb_socket_send_next(cweb_socket_t *self)
{
	int len = 0;
	int n = read(self->pipe[0], &len, sizeof(len));
	if(!n) return;
	if(!len) return;
	char buffer[LWS_PRE + len + LWS_PRE];
	n = read(self->pipe[0], buffer + LWS_PRE, len);
	if(!n) return;

	lws_write(self->wsi, buffer + LWS_PRE, len, LWS_WRITE_TEXT);

	if (poll(&(struct pollfd){ .fd = self->pipe[0], .events = POLLIN }, 1, 0)==1)
	{
		lws_callback_on_writable(self->wsi);
	}
}

void cweb_socket_send(cweb_socket_t *self, const char *message, size_t len)
{
	if(len && self->wsi)
	{
		int l = (int)len;
		write(self->pipe[1], &l, sizeof(l));
		write(self->pipe[1], message, len);
		lws_callback_on_writable(self->wsi);
	}
}

static char *generate_emit_message(const char *emit_name, const json_t *data, int id)
{
	json_t *info = json_object();
	json_t *jname = json_string(emit_name);
	json_t *jid = json_integer(id);
	json_object_set(info, "event", jname);
	json_object_set(info, "cbi", jid);
	json_decref(jname);
	json_decref(jid);

	if(data != NULL)
	{
		json_t *jdata = json_deep_copy(data);
		/* TODO: Remove unnecssary copy */
		json_object_set(info, "data", jdata);
		json_decref(jdata);
	}

	char *message = json_dumps(info, 0);

	json_decref(info);

	return message;
}

void cweb_socket_emit(cweb_socket_t *self, const char *event, const json_t *data,
		cweb_socket_response_t response)
{
	int id = self->ms_id++;
	if(response)
	{
		cweb_response_t *res;
		int i;
		for(res = self->responses, i = 0;
				res->id && i < self->responses_num;
				res++, i++);
		if(i == self->responses_num)
		{
			size_t l = self->responses_num + 1;
			self->responses = realloc(self->responses,
					(sizeof *self->responses)*l);
			self->responses_num = l;
			res = &self->responses[l - 1];
		}
		res->id = id;
		res->cb = response;

	}
	char *message = generate_emit_message(event, data, id);
	cweb_socket_send(self, message, strlen(message));
	free(message);
}

cweb_room_t *cweb_get_room(cweb_t *self, const char *room)
{
	int i;
	for(i = 0; i < self->rooms_num; i++)
	{
		if(!strcmp(room, self->rooms[i]->name))
		{
			return self->rooms[i];
		}
	}
	return NULL;
}

cweb_room_t *cweb_socket_get_room(cweb_socket_t *self, const char *room)
{
	return cweb_get_room(cweb_socket_get_server(self), room);
}

void cweb_to_room_send(cweb_t *self, const char *room_name,
		const char *message, size_t len, const cweb_socket_t *except)
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
		const char *event, const json_t *data,
		cweb_socket_response_t res, const cweb_socket_t *except)
{
	int i;
	cweb_room_t *room = cweb_get_room(self, room_name);
	if(!room) return;

	for(i = 0; i < room->sockets_num; i++)
	{
		cweb_socket_t *socket = room->sockets[i];
		if(socket && socket->wsi && socket != except)
		{
			cweb_socket_emit(socket, event, data, res);
		}
	}

}

void cweb_socket_to_room_emit(cweb_socket_t *self, const char *room,
		const char *event, const json_t *data, cweb_socket_response_t res,
		const cweb_socket_t *except)
{
	cweb_to_room_emit(cweb_socket_get_server(self), room, event, data, res, except);
}

static void cweb_socket_respond(cweb_socket_t *self, int id, const json_t *data)
{
	json_t *jdata = json_deep_copy(data);
	json_t *info = json_object();
	json_t *jid = json_integer(id);
	json_object_set(info, "id", jid);
	json_object_set(info, "data", jdata);
	cweb_socket_emit(self, "cweb_cb", info, NULL);
	json_decref(info);
	json_decref(jid);
	json_decref(jdata);
}

static cweb_socket_response_t cweb_socket_response(cweb_socket_t *self,
		int id, const json_t *data)
{
	int i;
	for(i = 0; i < self->responses_num; i++)
	{
		cweb_response_t *res = &self->responses[i];
		if(res->id == id)
		{
			res->id = 0;
			res->cb(self, id, data);
		}
	}
}

static void cweb_socket_got_response(cweb_socket_t *self, const json_t *data,
		int id, cweb_socket_response_t response)
{
	const json_t *jres_id = json_object_get(data, "cbi");
	int res_id = json_integer_value(jres_id);
	const json_t *jdata = json_object_get(data, "data");
	cweb_socket_response(self, id, jdata);
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
	json_t *json, *event, *data, *cb_id;
	switch(reason)
	{

	case LWS_CALLBACK_ESTABLISHED:
		socket->server = server;
		socket->wsi = wsi;
		socket->ms_id = 1;
		if(!socket->pipe[0])
		{
			pipe(socket->pipe);
		}
		cweb_socket_on(socket, "cweb_cb", cweb_socket_got_response);
		cb = cweb_socket_get_event(socket, "connected");
		if(cb)
		{
			cb(socket, NULL, 0, NULL);
		}
		break;

	case LWS_CALLBACK_RECEIVE:
		json = json_loads(in, 0, &error);
		event = json_object_get(json, "event");
		data = json_object_get(json, "data");
		cb_id = json_object_get(json, "cbi");

		cb = cweb_socket_get_event(socket, json_string_value(event));
		if(cb)
		{
			int id = json_integer_value(cb_id);
			cb(socket, data, id, cweb_socket_respond);
		}
		json_decref(json);
		break;

	case LWS_CALLBACK_CLOSED:
		cb = cweb_socket_get_event(socket, "disconnected");
		if(cb)
		{
			cb(socket, NULL, 0, NULL);
		}
		close(socket->pipe[0]);
		close(socket->pipe[1]);
		socket->wsi = NULL;
		cweb_socket_leave_all(socket);
		break;
	case LWS_CALLBACK_SERVER_WRITEABLE:
		cweb_socket_send_next(socket);
		break;
	case LWS_CALLBACK_PROTOCOL_INIT:
		printf("Protocol started successfully.\n");
		break;
	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		/* you could return non-zero here and kill the connection */
		break;
	case LWS_CALLBACK_PROTOCOL_DESTROY:
		printf("Protocol being destroyed.\n");
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

static int cweb_socket_serve_string_fragment(cweb_socket_t *socket)
{
	if (socket->httpipe[0] == 0)
		goto try_to_reuse;

	int sent = 0;
	do {
		char buffer[1000];
		/* we'd like the send this much */
		int n = sizeof(buffer) - LWS_PRE;

		/* but if the peer told us he wants less, we can adapt */
		int m = lws_get_peer_write_allowance(socket->wsi);

		/* -1 means not using a protocol that has this info */
		if (m == 0)
		{
			/* right now, peer can't handle anything */
			goto later;
		}

		if (m != -1 && m < n)
		{
			/* he couldn't handle that much */
			n = m;
		}

		n = read(socket->httpipe[0], buffer + LWS_PRE, n);
		/* sent it all, close conn */
		if (n <= 0)
		{
			goto penultimate;
		}
		m = lws_write(socket->wsi, buffer + LWS_PRE, n, LWS_WRITE_HTTP);
		if (m < 0) {
			lwsl_err("write failed\n");
			/* write failed, close conn */
			goto bail;
		}
		if (m) /* while still active, extend timeout */
		{
			lws_set_timeout(socket->wsi, PENDING_TIMEOUT_HTTP_CONTENT, 5);
		}
		sent += m;

	} while (!lws_send_pipe_choked(socket->wsi) && (sent < 1024 * 1024));
later:
	lws_callback_on_writable(socket->wsi);
	return 0;
penultimate:
	close(socket->httpipe[0]); socket->httpipe[0] = 0;
	close(socket->httpipe[1]); socket->httpipe[1] = 0;
	goto try_to_reuse;

bail:
	close(socket->httpipe[0]); socket->httpipe[0] = 0;
	close(socket->httpipe[1]); socket->httpipe[1] = 0;
	return -1;

try_to_reuse:
	return -1;
	/* if(lws_http_transaction_completed(socket->wsi)) */
	/* { */
	/* 	return -1; */
	/* } */


}

static int lws_serve_http_string(cweb_socket_t *socket, unsigned char *string,
				    size_t stringlen, const char *content_type,
				    const char *other_headers, int other_headers_len)
{
	unsigned char buffer[4096 + LWS_PRE];

	unsigned char *p = buffer + LWS_PRE;
	unsigned char *start = p;
	unsigned char *end = p + sizeof(buffer) - LWS_PRE;

	int ret = -1;

	if(socket->httpipe[0]) close(socket->httpipe[0]);
	if(socket->httpipe[1]) close(socket->httpipe[1]);
	pipe(socket->httpipe);
	int n = write(socket->httpipe[1], string, stringlen);
	int flags = fcntl(socket->httpipe[0], F_GETFL, 0);
	fcntl(socket->httpipe[0], F_SETFL, flags | O_NONBLOCK);


	if(lws_add_http_header_status(socket->wsi, 200, &p, end))
		return 1;
	if(lws_add_http_header_by_token(socket->wsi, WSI_TOKEN_HTTP_SERVER,
					 (unsigned char *)"libwebsockets", 13,
					 &p, end))
		return 1;
	if(lws_add_http_header_by_token(socket->wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					 (unsigned char *)content_type,
					 strlen(content_type), &p, end))
		return 1;
	if(lws_add_http_header_content_length(socket->wsi, n, &p, end))
		return 1;

	if(other_headers) {
		if((end - p) < other_headers_len)
			return 1;
		memcpy(p, other_headers, other_headers_len);
		p += other_headers_len;
	}

	if(lws_finalize_http_header(socket->wsi, &p, end))
		return 1;

	ret = lws_write(socket->wsi, start, p - start, LWS_WRITE_HTTP_HEADERS);
	if(ret < 0)
		return 1;

	/* memcpy(p + LWS_PRE, string, stringlen); */

	/* ret = lws_write(socket->wsi, p + LWS_PRE, stringlen, LWS_WRITE_HTTP); */
	/* if(ret < 0) */
		/* return 1; */
	ret = cweb_socket_serve_string_fragment(socket);
	return ret;
}

static void dump_handshake_info(struct lws *wsi)
{
	int n = 0, len;
	char buf[256];
	const unsigned char *c;

	do
	{
		c = lws_token_to_string(n);
		if(!c) {
			n++;
			continue;
		}

		len = lws_hdr_total_length(wsi, n);
		if(!len || len > sizeof(buf) - 1) {
			n++;
			continue;
		}

		lws_hdr_copy(wsi, buf, sizeof buf, n);
		buf[sizeof(buf) - 1] = '\0';

		fprintf(stderr, "    %s = %s\n", (char *)c, buf);
		n++;
	}
	while (c);
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
	cweb_socket_t *socket = cwebuser;
	if(socket)
	{
		socket->wsi = wsi;
	}

	static char cwd[1024] = "";
	if(cwd[0] == '\0')
	{
		if(!getcwd(cwd, sizeof(cwd)))
		{
			fprintf(stderr, "Could not get working directory!");
		}
	}

	char buf[256];
	switch (reason)
	{
		case LWS_CALLBACK_HTTP_BODY:
			strncpy(buf, in, 20);
			buf[20] = '\0';
			if (len < 20)
				buf[len] = '\0';

			lwsl_notice("LWS_CALLBACK_HTTP_BODY: %s... len %d\n",
					(const char *)buf, (int)len);

			break;

		case LWS_CALLBACK_HTTP_BODY_COMPLETION:
			lwsl_notice("LWS_CALLBACK_HTTP_BODY_COMPLETION\n");
			/* the whole of the sent body arrived, close or reuse the connection */
			lws_return_http_status(wsi, HTTP_STATUS_OK, NULL);
			goto try_to_reuse;

		case LWS_CALLBACK_HTTP_FILE_COMPLETION:
			goto try_to_reuse;

		case LWS_CALLBACK_HTTP_WRITEABLE:
			lwsl_info("LWS_CALLBACK_HTTP_WRITEABLE\n");
			return cweb_socket_serve_string_fragment(socket);
		case LWS_CALLBACK_CLIENT_WRITEABLE:
			printf("connection established\n");
			break;
		case LWS_CALLBACK_HTTP:
			{
				{
					/* dump_handshake_info(wsi); */
					int n = 0;
					char buf[256];
					while (lws_hdr_copy_fragment(wsi, buf, sizeof(buf),
								WSI_TOKEN_HTTP_URI_ARGS, n) > 0) {
						lwsl_notice("URI Arg %d: %s\n", ++n, buf);
					}
				}
				char *resource_path;
				int cweb_resources = 0;
				char *requested_uri = (char *) in;
				/* printf("requested URI: %s\n", requested_uri); */

				cweb_redirect_t *redir = cweb_get_redirect(server, requested_uri);
				if(redir)
				{
					printf("redirecting from %s to %s\n", redir->from, redir->to);
					const size_t response_len = LWS_PRE + 512;
					unsigned char buf[response_len];
					/* void *universal_response = "Hello, World!"; */

					unsigned char *p = buf + LWS_PRE;
					unsigned char *end = p + 512 - LWS_PRE;

					/* lws_add_http_header_content_length(wsi, 0, &p, end); */
					lws_add_http_header_status(wsi, 301, &p, end);
					lws_add_http_header_by_token(wsi,
							WSI_TOKEN_HTTP_LOCATION,
							redir->to, strlen(redir->to), &p, end);

					lws_finalize_http_header(wsi, &p, end);

					*p = '\0';
					lws_write(wsi, buf + LWS_PRE, p - (buf + LWS_PRE), LWS_WRITE_HTTP_HEADERS);
					return -1;
				}

				if(strncmp(requested_uri, "/cweb/", sizeof("/cweb/") - 1) == 0)
				{
					requested_uri += sizeof("/cweb/") - 2;
					cweb_resources = 1;
				}

				if(cwd != NULL)
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
							int n = lws_serve_http_file(wsi, "missing", ft->mime, NULL, 0);
							if(n < 0 || ((n > 0) && lws_http_transaction_completed(wsi)))
							{
								return -1;
							}
						}
						else
						{
							int n = lws_serve_http_string(socket, buffer, (size_t)len, ft->mime, NULL, 0);
							free(buffer);
							return n;
						}
					}
					else
					{
						int n = lws_serve_http_file(wsi, resource_path, ft->mime, NULL, 0);
						if(n < 0 || ((n > 0) && lws_http_transaction_completed(wsi)))
						{
							return -1;
						}
					}
				}
				goto try_to_reuse;
			}
		case LWS_CALLBACK_PROTOCOL_DESTROY:
			printf("Protocol being destroyed.\n");
			break;
		default:
			/* printf("unhandled callback\n"); */
			break;
	}

	return 0;

try_to_reuse:
	if(lws_http_transaction_completed(wsi))
	{
		return -1;
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

	cweb_add_protocol(self, "http-only", cweb_http_protocol, sizeof(cweb_socket_t));

	memset(&self->info, 0, sizeof(self->info));
	self->info.port = port;

	self->info.iface = NULL;
	self->info.protocols = self->protocols;
	self->info.extensions = NULL;

	self->redirects = NULL;
	self->redirects_num = 0;

	self->rooms = NULL;
	self->rooms_num = 0;

	self->events = NULL;
	self->events_num = 0;

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

	int n = 0;
	while(n >= 0)
	{
		n = lws_service(context, 50);
	}

	lws_context_destroy(context);

	if(self->events) free(self->events);
	if(self->rooms) free(self->rooms);
	int i;
	for(i = 0; i < self->redirects_num; i++)
	{
		free(self->redirects[i].from);
		free(self->redirects[i].to);
	}
	if(self->redirects) free(self->redirects);

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

	cweb_room_t *room = self->rooms[l - 1] = malloc(sizeof *room);
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
	for(room_iter = self->rooms; *room_iter; room_iter++);
	(*room_iter) = room;
}

void cweb_socket_print_rooms(const cweb_socket_t *self)
{
	int i;
	for(i = 0; self->rooms[i]; i++)
	{
		printf("%s\n", self->rooms[i]->name);
	}
}

static void cweb_room_remove_socket(cweb_room_t *self, const cweb_socket_t *socket)
{
	int i;
	for(i = 0; i < self->sockets_num; i++)
	{
		if(self->sockets[i] == socket)
		{
			printf("removing socket from room '%s' ^_^\n", self->name);
			self->sockets[i] = NULL;
			break;
		}
	}
}

void cweb_socket_leave(cweb_socket_t *self, const char *room_name)
{
	cweb_t *server = cweb_socket_get_server(self);
	cweb_room_t *room = cweb_get_room(server, room_name);
	if(!room)
	{
		return;
	}

	cweb_room_remove_socket(room, self);

	cweb_room_t **room_iter;
	for(room_iter = self->rooms; *room_iter; room_iter++)
	{
		if(*room_iter == room)
		{
			cweb_room_t **room_jter;
			for(room_jter = room_iter; *room_jter; room_jter++)
			{
				*room_jter = *(room_jter + 1);
			}
			break;
		}
	}
}

void cweb_socket_leave_all(cweb_socket_t *self)
{
	cweb_room_t **room_iter;
	for(room_iter = self->rooms; *room_iter; room_iter++)
	{
		cweb_room_remove_socket(*room_iter, self);
		*room_iter = NULL;
	}
}

int cweb_socket_inside(cweb_socket_t *self, const char *room_name)
{
	cweb_t *server = cweb_socket_get_server(self);
	cweb_room_t *room = cweb_get_room(server, room_name);

	cweb_room_t **room_iter;
	for(room_iter = self->rooms; *room_iter; room_iter++)
	{
		if(*room_iter == room)
		{
			return 1;
		}
	}
	return 0;
}
