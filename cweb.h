#ifndef CWEB_H
#define CWEB_H

#include <jansson.h>

typedef struct cweb_t cweb_t;
typedef struct cweb_socket_t cweb_socket_t;

typedef struct cweb_room_t
{
	char name[32];
	cweb_socket_t **sockets;
	size_t sockets_num;
} cweb_room_t;
/* TODO: make cweb_room_t private */

typedef void(*event_callback_t)(cweb_socket_t *self, const json_t *data);

cweb_t *cweb_new(const int port);

int cweb_run(cweb_t *self);

void *cweb_get_user_ptr(cweb_t *self);
void cweb_set_user_ptr(cweb_t *self, void *userptr);

void cweb_sockets_on(cweb_t *self, const char *event, event_callback_t cb);

void cweb_set_public(cweb_t *self, const char *dir);

cweb_room_t *cweb_get_room(cweb_t *self, const char *room);

void cweb_to_room_send(cweb_t *self, const char *room_name,
		const char *message, size_t len, cweb_socket_t *except);

/* socket */

void cweb_socket_set_user_ptr(cweb_socket_t *self, void *userptr);

void cweb_socket_on(cweb_socket_t *self, const char *event, event_callback_t cb);

cweb_t *cweb_socket_get_server(cweb_socket_t *self);

void cweb_socket_send(cweb_socket_t *self, const char *message, size_t len);

void cweb_socket_emit(cweb_socket_t *self, const char *event, json_t *data);

void *cweb_socket_get_user_ptr(cweb_socket_t *self);
void cweb_socket_set_user_ptr(cweb_socket_t *self, void *userptr);

void cweb_socket_join(cweb_socket_t *self, const char *room_name);

cweb_room_t *cweb_socket_get_room(cweb_socket_t *self, const char *room);

void cweb_socket_to_room_emit(cweb_socket_t *self, const char *room,
		const char *event, json_t *data, cweb_socket_t *except);

/* TODO:vector */


#endif /* !CWEB_H */
