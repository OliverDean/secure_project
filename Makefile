CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c11

all: crypto_1

crypto_1: cli.o crypto.o main.o
	$(CC) $(CFLAGS) -o crypto_1 cli.o crypto.o main.o

cli.o: cli.c crypto.h
	$(CC) $(CFLAGS) -c cli.c

crypto.o: crypto.c crypto.h
	$(CC) $(CFLAGS) -c crypto.c

main.o: main.c crypto.h
	$(CC) $(CFLAGS) -c main.c

test: all
	./crypto_1 caesar-encrypt 5 "THIS IS A MUCH LONGER TEXT TO ENCRYPT USING CAESAR CIPHER"
	./crypto_1 caesar-decrypt 5 "YMNX NX F RZHM QTSLJW YJCY YT JSHWDUY ZXNSL HFJXFW HNUMJW"
	./crypto_1 vigenere-encrypt "COMPLEXKEY" "THIS IS A MUCH LONGER TEXT TO ENCRYPT USING VIGENERE CIPHER"
	./crypto_1 vigenere-decrypt "COMPLEXKEY" "VVUH TW X WYAJ ZACRIO DIVV HA TYGOITR WGUCR ZFQILGFQ RTTEOV"

clean:
	rm -f crypto_1 *.o
