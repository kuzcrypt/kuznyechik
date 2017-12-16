TARGET = test

.PHONY: all clean

all:
	$(CC) test.c kuznyechik.c -o xtest -march=native -DHAVE_SSE2 -Ofast
	./xtest

clean:
	$(RM) -f $(TARGET)
