TARGET = test

.PHONY: all clean

all: $(TARGET)
	./$(TARGET)

$(TARGET): test.c kuznyechik.c kuznyechik.h
	$(CC) test.c kuznyechik.c -o $@

clean:
	$(RM) -f $(TARGET)
