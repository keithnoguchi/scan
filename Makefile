CFLAGS = -I.
CXXFLAGS = -I/usr/local/include
LDXXFLAGS = -L/usr/local/lib -lCppUTest
TARGET = scanner
TEST_TARGET = tests/test
SRC := scanner.c scanner4_tcp.c
OBJ := $(SRC:.c=.o)
TMP := *~ *.swp a.out **/*~ **/*.swp **/a.out
DEPS = utils.h scanner.h
TEST = tests/test_main.c tests/test_scanner.c
TEST_OBJ := $(TEST:.c=.o)

.PHONY: all test clean
all: $(TARGET)
$(TARGET): main.o $(OBJ)
	$(CC) -o $@ $^

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

test: $(TEST_TARGET)
	./$(TEST_TARGET) -c

$(TEST_TARGET): $(OBJ) $(TEST_OBJ)
	$(CXX) -o $@ $^ $(LDXXFLAGS)

tests/%.o: tests/%.c $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS)

clean:
	$(RM) $(OBJ) $(TEST_OBJ) $(TMP) $(TARGET) $(TEST_TARGET)
