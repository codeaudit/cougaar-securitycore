AR = ar
GFLAGS =
GET = get
ASFLAGS =
MAS = mas
AS = as
FC = f77
CFLAGS =-g
CC = gcc
LDFLAGS =
LD = ld
LFLAGS =
LEX = lex
YFLAGS =
YACC = yacc
LOADLIBS =
MAKE = make
MAKEARGS = 'SHELL=/bin/sh'
SHELL = /bin/sh
MAKEFLAGS = b

all:		vulnerable attacker exploit4 echo_server echo_client test1

attacker:	eggshell.c
	$(CC) $(CFLAGS) $? $(LDFLAGS) -o $@

exploit4:	exploit4.c
	$(CC) $(CFLAGS) $? $(LDFLAGS) -o $@

vulnerable:	vulnerable.c
	$(CC) $(CFLAGS) $? $(LDFLAGS) -o $@

test1:	test1.c
	$(CC) $(CFLAGS) $? $(LDFLAGS) -o $@

echo_client:	echo_client.c
	$(CC) $(CFLAGS) $? $(LDFLAGS) -o $@

echo_server:	echo_server.c
	$(CC) $(CFLAGS) $? $(LDFLAGS) -o $@

clean:
	rm -f vulnerable echo_client echo_server exploit4 attacker test1 *~

.PHONY:	clean all

