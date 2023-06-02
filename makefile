#
# 

BINDIR=bin
INTDIR=$(BINDIR)/int

CFLAGS=-Wall -Wextra -O2 -pedantic -c

full: init main.o proc.o so.o test.o
	gcc $(INTDIR)/main.o $(INTDIR)/proc.o -o $(BINDIR)/injector
	gcc -shared -ldl $(INTDIR)/so.o -o $(BINDIR)/libinjectme.so
	gcc $(INTDIR)/test.o -o $(BINDIR)/test

main.o: main.c 
	gcc main.c $(CFLAGS) -o $(INTDIR)/main.o

proc.o: proc.c
	gcc proc.c $(CFLAGS) -o $(INTDIR)/proc.o

so.o: so.c
	gcc so.c $(CFLAGS) -fPIC -o $(INTDIR)/so.o

test.o: test.c
	gcc test.c $(CFLAGS) -o $(INTDIR)/test.o

init:
	mkdir -p $(BINDIR) $(INTDIR)

clean:
	rm -rf $(INTDIR) $(BINDIR)
