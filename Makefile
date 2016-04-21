.PHONY:clean

all:server

server:server.c
	gcc server.c -o server -lwebsockets -g3

clean:
	-rm server
