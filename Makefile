.PHONY:clean

all: server cemplate.o

server: cweb.c cemplate.c
	cc -c cemplate.c -o cemplate.o
	cc cemplate.c -o cemplate -ldl -DUNIT_TEST
	cc cweb.c -o server cemplate.o -ldl -lwebsockets -ljansson -g3

clean:
	-rm cemplate.o
	-rm cemplate
	-rm -r templates
	-rm server
