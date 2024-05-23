CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c11

all: final

final: final.o
	$(CC) $(CFLAGS) -o final final.o

final.o: final.c crypto.h
	$(CC) $(CFLAGS) -c final.c

test: all
	./final caesar-encrypt 5 "THIS IS A MUCH LONGER TEXT TO ENCRYPT USING CAESAR CIPHER"
	./final caesar-decrypt 5 "YMNX NX F RZHM QTSLJW YJCY YT JSHWDUY ZXNSL HFJXFW HNUMJW"
	./final vigenere-encrypt "COMPLEXKEY" "THIS IS A MUCH LONGER TEXT TO ENCRYPT USING VIGENERE CIPHER"
	./final vigenere-decrypt "COMPLEXKEY" "VVUH TW X WYAJ ZACRIO DIVV HA TYGOITR WGUCR ZFQILGFQ RTTEOV"

clean:
	rm -f final *.o
