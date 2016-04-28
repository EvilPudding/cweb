.PHONY:clean

all: server cemplate.o

server: cweb.c cemplate.c server.c
	cc -c cemplate.c -o cemplate.o
	cc -c cweb.c -o cweb.o
	cc server.c -o server cweb.o cemplate.o -ldl -lwebsockets -ljansson -g3

clean:
	-rm cemplate.o
	-rm cweb.o
	-rm -r templates
	-rm server
