SRC = main.c
OBJ = main.o
BINARY = ropdumper

CFLAGS  ?= -D_FORTIFY_SOURCE=2 -O2 -fstack-protector --param=ssp-buffer-size=4 -Wall -Wformat-security -Werror
LDFLAGS ?= -lbfd
RM      ?= rm -f

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
