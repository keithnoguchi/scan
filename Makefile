SUDO := sudo
CFLAGS = -I. -g -D_GNU_SOURCE
CXXFLAGS = -I. -I/usr/local/include
LDXXFLAGS = -L/usr/local/lib -lCppUTest
TARGET = scanner
TEST_TARGET = tests/test
TEST_OPS := -c -v
SRC := scanner.c \
	scanner4.c scanner4_tcp.c \
	scanner6.c scanner6_tcp.c
OBJ := $(SRC:.c=.o)
TMP := *~ *.swp a.out **/*~ **/*.swp **/a.out
DEPS = utils.h scanner.h scanner.h \
       scanner4.h scanner4_tcp.h \
       scanner6.h scanner6_tcp.h
TEST = tests/test_main.c tests/test_scanner.c
TEST_OBJ := $(TEST:.c=.o)

.PHONY: all test clean
all: $(TARGET)
$(TARGET): main.o $(OBJ)
	$(CC) -o $@ $^

test: $(TEST_TARGET)
	$(SUDO) ./$(TEST_TARGET) $(TEST_OPS)
$(TEST_TARGET): $(TEST_OBJ) $(OBJ)
	$(CXX) -o $@ $^ $(LDXXFLAGS)

tests/%.o: tests/%.c $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	$(RM) $(OBJ) $(TEST_OBJ) $(TMP) $(TARGET) $(TEST_TARGET)
