#name of output file
NAME = pcap
#build dir
BD = ./build

#Linker flags
LDLIBS +=
LDDIRS += -L$(BD)

#Compiler flags
#-w to remove all warnings
CFLAGS += -Wall -Wextra -Wno-unused-parameter -O3
I += -I./
LIB += -lpcap

#Compiler
CC = gcc -ggdb
AR = ar

#SRC=$(wildcard *.c)
LIBNAME = pcap_dhcp
SRC_LIB = pcap_dhcp.c
SRC_BIN = main.c
SRC = $(SRC_LIB) $(SRC_BIN)

all: $(NAME) static shared

$(NAME): $(SRC)
		mkdir -p build
		$(CC) $(CFLAGS) $(I) $(LDDIRS) $(LDLIBS) $^ -o build/$(NAME) $(LIB)

staticlib:
		$(CC) $(CFLAGS) $(I) $(LDDIRS) $(LDLIBS) $(SRC_LIB) -c -o $(BD)/lib$(LIBNAME).a
		#$(AR) rcs build/lib$(LIBNAME).a build/lib$(LIBNAME).o

sharedlib:
		$(CC) $(CFLAGS) $(I) $(LDDIRS) $(LDLIBS) $(SRC_LIB) -shared -fPIC -o $(BD)/lib$(LIBNAME).so

shared: sharedlib
		$(CC) $(CFLAGS) $(I) $(LDDIRS) $(LDLIBS) $(SRC_BIN) -L./build -Wl,-Bdynamic -l$(LIBNAME) $(LIB) -o $(BD)/$(NAME)_shared

static: staticlib
		$(CC) $(CFLAGS) $(I) $(LDDIRS) $(LDDIRS) $(SRC_BIN) -Wl,-Bstatic -l$(LIBNAME) $(LIB) -Wl,-Bdynamic -o $(BD)/$(NAME)_static

clean:
		rm -rf $(BD)/*
