.PHONY:clean

all: server cemplate.o

server: server.c cemplate.c
	cc -c cemplate.c -o cemplate.o
	cc cemplate.c -o cemplate -ldl -DUNIT_TEST
	cc server.c -o server cemplate.o -ldl -lwebsockets -g3

clean:
	-rm server
