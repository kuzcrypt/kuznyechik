TARGET = xtest

.PHONY: all clean

all:
	$(CC) test.c kuznyechik.c -o xtest -Ofast -march=native -DHAVE_SSE2
	./$(TARGET)

clean:
	$(RM) $(TARGET)
