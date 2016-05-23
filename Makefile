CC=gcc
CFLAGS=-I.
OBJ = xmppagent.o xmppagent.o 

LIBS=-lstrophe

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

xmppagent: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
clean:
	rm -f *.o xmppagent
