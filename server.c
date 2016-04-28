#include <string.h>

#include "cweb.h"

typedef struct { int number; } Server;
typedef struct { char *name; } Client;

void socket_message(cweb_socket_t *socket, const json_t *data)
{
	printf("Received message: '%s'\n", json_string_value(data));
}

void sockets_connected(cweb_socket_t *socket, const json_t *data)
{
	char name[64];

	Server *server = cweb_get_user_ptr(cweb_socket_get_server(socket));
	server->number++;

	sprintf(name, "anon%d", server->number);

	Client *client = malloc(sizeof(*client));

	cweb_socket_on(socket, "message", socket_message);

	cweb_socket_join(socket, "main_room");

	json_t *info = json_object();
	json_t *jname = json_string(name);
	json_object_set(info, "name", jname);
	cweb_socket_to_room_emit(socket, "main_room", "joined", info, socket);
	json_decref(jname);
	json_decref(info);

	client->name = strdup(name);
	cweb_socket_set_user_ptr(socket, client);

	cweb_room_t *room = cweb_socket_get_room(socket, "main_room");
	size_t l = room->sockets_num;

	for(int i = 0; i < l; i++)
	{
		if(room->sockets[i] && room->sockets[i] != socket)
		{
			Client *other_client = cweb_socket_get_user_ptr(room->sockets[i]);
			json_t *other_info = json_object();
			json_t *other_name = json_string(other_client->name);
			json_object_set(other_info, "name", other_name);
			cweb_socket_emit(socket, "joined", other_info);
			json_decref(other_name);
			json_decref(other_info);
		}
	}
}

void sockets_disconnected(cweb_socket_t *socket, const json_t *data)
{
	Client *client = cweb_socket_get_user_ptr(socket);
	json_t *info = json_object();
	json_t *jname = json_string(client->name);
	json_object_set(info, "name", jname);
	cweb_socket_to_room_emit(socket, "main_room", "left", info, socket);
	json_decref(jname);
	json_decref(info);
	free(client->name);
	free(client);
}

int main(int argc, char **argv)
{
	int port = 80;
	Server *server_data = malloc(sizeof(*server_data));

	cweb_t *server = cweb_new(80);
	cweb_set_user_ptr(server, server_data);
	cweb_set_public(server, "public");

	cweb_sockets_on(server, "connected", sockets_connected);
	cweb_sockets_on(server, "disconnected", sockets_disconnected);

	cweb_run(server);

	free(server_data);
}

