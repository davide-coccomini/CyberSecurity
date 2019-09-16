CC = g++
CFLAGS = -Wall

all: clientC serverC

code: 
	code server/server.cpp client/client.cpp communication.cpp &

clientC: client
	$(CC) $(CFLAGS) client/client.cpp -o client/client -lcrypto -lstdc++fs

serverC: server
	$(CC) $(CFLAGS) server/server.cpp -o server/server -lcrypto -lstdc++fs

runs:
	./server/server

runc:
	./client/client

clean:
	rm server/server client/client
