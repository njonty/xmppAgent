CC=gcc
CFLAGS=-I. -DOPENWRT
OBJ = xuci.o xmppAgent.o

LIBS=-lstrophe -lpthread -luci

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

xmppAgent: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
clean:
	rm -f *.o xmppAgent

