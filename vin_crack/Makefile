CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c11

all: vigenere_crack

vigenere_crack: vigenere_crack.c
	$(CC) $(CFLAGS) -o vigenere_crack vigenere_crack.c -lm

test: all
	./vigenere_crack cat_story_KEY.txt

clean:
	rm -f vigenere_crack
