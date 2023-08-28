# qked

SRC = qked.c
OBJ = $(SRC:.c=.o)

CFLAGS += -Wall -I/usr/include/libnl3/
LDFLAGS += -L/usr/lib/x86_64-linux-gnu/ -lnl-3 -lnl-genl-3 -levent

.c.o:
	$(CC) $(CFLAGS) -c $<

qked: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)
