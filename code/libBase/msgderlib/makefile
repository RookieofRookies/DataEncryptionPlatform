# Makefile Module For Develop Team

.SUFFIXES:
.SUFFIXES:  .c .o

WORKDIR=.
INCLDIR=$(WORKDIR)/incl
LIBDIR=$(HOME)/lib
BINDIR=$(HOME)/bin

CC=gcc

INCLFLG= -I$(INCLDIR)
LIBFLG = -L$(LIBDIR)
CFLAG= -c -g $(INCLFLG) 
LIBS = 

VPATH = $(WORKDIR)/src

OBJ7 = itcast_asn1_der.o itcastderlog.o  keymng_msg.o 


libmessagereal.so: $(OBJ7) 
	$(CC) -shared -fPIC $^ -o $@ 
	@cp $@ $(LIBDIR)

.c.o:
#	$(CC) -shared -fPIC $(CFLAG) $< -D_ITCAST_OS_LINUX  -DMEMWATCH -DMW_STDIO
	$(CC) -shared -fPIC $(CFLAG) $< -D_ITCAST_OS_LINUX

	
	
.PHONY : clean
clean :
	rm  -f *.o
	rm  -f *.s
