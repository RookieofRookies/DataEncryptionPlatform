.PHONY:clean all

WORKDIR=.
VPATH = ./src

CC=gcc
CFLGS= -Wall -g -I$(WORKDIR)/inc/
LIBFLAG = -L$(WORKDIR)/lib


BIN = keymngclient  keymngserver keymngcrypt


all:$(BIN)

keymngclient:keymngclient.o  keymnglog.o  keymngclientop.o  myipc_shm.o keymng_shmop.o
	$(CC) $(LIBFLAG) $^ -o $@ -lpthread -litcastsocket -lmessagereal  -lappinterface

keymngserver:keymngserver.o  keymngserverop.o  keymnglog.o  myipc_shm.o  keymng_shmop.o 
	$(CC) $(LIBFLAG) $^ -o $@ -lpthread -litcastsocket -lmessagereal  -lappinterface

keymngcrypt:keymngcrypt.o  keymngcryptop.o  keymnglog.o  myipc_shm.o  keymng_shmop.o 
	$(CC) $(LIBFLAG) $^ -o $@ -lpthread -litcastsocket -lmessagereal  -lappinterface
 		
%.o:%.c
	$(CC) $(CFLGS) -c $< -o $@	

clean:
	rm -f *.o $(BIN) *_out
	
	
	




