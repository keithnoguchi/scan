CFLAGS = -I.
TARGET = scanner
SRC := main.c scanner.c scanner4_tcp.c
OBJ := $(SRC:.c=.o)
TMP := *~ *.swp a.out
DEPS = utils.h scanner.h

.PHONY: all scanner clean
all: $(TARGET)
$(TARGET): $(OBJ)
	$(CC) -o $@ $^

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	$(RM) $(OBJ) $(TMP) $(TARGET)
