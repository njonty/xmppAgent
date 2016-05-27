CC=gcc
CFLAGS=-I.
OBJ = xmppAgent.o

LIBS=-lstrophe

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

xmppAgent: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
clean:
	rm -f *.o xmppAgent
