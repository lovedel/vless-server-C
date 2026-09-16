CC       ?= gcc
AR        = ar
LIB_WS    = libws.a
CFLAGS   += -Wall -Wextra -O2 -std=c99 -pedantic
CFLAGS   += -I include -I wsserver-include
LDLIBS    = $(LIB_WS) -pthread
ARFLAGS   = cru

WS_OBJ = wsserver-src/base64.o \
	wsserver-src/handshake.o   \
	wsserver-src/sha1.o        \
	wsserver-src/utf8.o        \
	wsserver-src/ws.o

all: vless-server

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB_WS): $(WS_OBJ)
	$(AR) $(ARFLAGS) $(LIB_WS) $^

vless-server: src/main.o $(LIB_WS)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f $(WS_OBJ) $(LIB_WS) src/main.o vless-server

.PHONY: all clean
