TARGET		= ntp_proxy
DEBUG		= -g3
LIBS 		= -lm
CC 		= g++
CFLAGS		= -std=g++14 -Wall -Wextra -fsanitize=address
HEADERS		= ../inc/
.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.cpp))
HEADERS := $(wildcard *.h)

%.o: %.cpp $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -o $@

clean:
	rm -f *.o *~ $(TARGET)
