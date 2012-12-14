SRC = main.c
OBJ = main.o
BINARY = ropdumper
CFLAGS ?= -O2 -fstack-protector -Wall -Werror
LDFLAGS ?= -lbfd

ifeq ($(DEBUG),1)
CFLAGS += -g -DDEBUG_ENABLED
endif

$(info Compiling with CFLAGS $(CFLAGS))
$(info Linking with LDFLAGS $(LDFLAGS))

$(BINARY): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	$(RM) $(OBJ) $(BINARY)

.PHONY: clean
