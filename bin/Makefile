# qked

SRC = qked.c ngtcp_picotls.c
OBJ = $(SRC:.c=.o)

CFLAGS += -Wall -I/usr/include/libnl3/ -I./picotls/include/ -I.
LDFLAGS += picotls/libpicotls-core.a picotls/libpicotls-openssl.a 
LDFLAGS += -L/usr/lib/x86_64-linux-gnu/ -lnl-3 -lnl-genl-3 -levent -lcrypto -lssl

.c.o:
	$(CC) $(CFLAGS) -c $<

qked: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f qked $(OBJ)
