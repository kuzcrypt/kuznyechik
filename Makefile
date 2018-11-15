TARGET = test

.PHONY: all clean

all:
	$(CC) test.c kuznyechik.c -o xtest -Ofast -march=native -DHAVE_SSE2
	./xtest

clean:
	$(RM) -f $(TARGET)
