CC=gcc
#CFLAGS=-c -Wall -Werror -g -DDEBUG
#LDFLAGS=-static
CFLAGS=-s -c -Wall -Werror
LDFLAGS=-s -static
SOURCES=*.c
OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
EXECUTABLE=minetunnel

all: clean $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(@) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $< -o $(@)

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
