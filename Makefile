SRC = main.c
OBJ = main.o
BINARY = ropdumper
CFLAGS ?= -g -O2 -fstack-protector -Wall -Werror
LDFLAGS ?= -lbfd

$(BINARY): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	$(RM) $(OBJ) $(BINARY)

.PHONY: clean
