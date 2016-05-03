.PHONY:clean

all: server

server: server.c libcweb.so
	cc server.c -o server -I. ./libcweb.so -ldl -lwebsockets -ljansson -g3

libcweb.so: cweb.c cemplate.c
	$(CC) -fPIC -O2 -c cemplate.c -o cemplate.o
	$(CC) -fPIC -O2 -c cweb.c -o cweb.o
	$(CC) -shared cweb.o cemplate.o -o libcweb.so

install:
	cp libcweb.so /usr/lib
	cp cweb.h /usr/include
	mkdir -p /usr/share/cweb
	cp -r resources /usr/share/cweb

clean:
	-rm cemplate.o
	-rm libcweb.so
	-rm cweb.o
	-rm -r templates
	-rm server
