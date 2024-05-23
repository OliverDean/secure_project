CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -std=c11

all: caesar_crack

caesar_crack: caesar_crack.c
	$(CC) $(CFLAGS) -o caesar_crack caesar_crack.c

test: all
	./caesar_crack cat_story_rot13.txt

clean:
	rm -f caesar_crack
