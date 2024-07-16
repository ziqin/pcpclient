CFLAGS = -std=c2x -Wall -Wextra

all: pcpclient

pcpclient: main.o client.o message.o buffer.o network.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

main.o: main.c client.h

client.o: client.c client.h message.h network.h

message.o: message.c message.h buffer.h

buffer.o: buffer.c buffer.h

network.o: network.c network.h

.PHONY: clean

clean:
	$(RM) *.o pcpclientd
