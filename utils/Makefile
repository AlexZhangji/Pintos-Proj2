all: setitimer-helper squish-pty squish-unix

CC = gcc
CFLAGS = -Wall -W
LDFLAGS = -lm

setitimer-helper: setitimer-helper.c
	gcc -o setitimer-helper setitimer-helper.c -lm

squish-pty: squish-pty.c
	gcc -o squish-pty squish-pty.c -lm

squish-unix: squish-unix.c
	gcc -o squish-unix squish-unix.c -lm
clean: 
	rm -f *.o setitimer-helper squish-pty squish-unix
