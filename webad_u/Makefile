#makefile

SRC 			= $(wildcard *.c)
OBJS 			= $(patsubst %.c,%.o,$(SRC))

APP_INCLUDE += -I./include
LIBRARY	=  -lpthread -lm

TARGET			= webad

CFLAGS 			= $(CFLAGS_EXTRA) -Wall -g -o  


all: $(TARGET)
	@echo Generation TARGET
$(TARGET):
	$(CC) $(CFLAGS) $(TARGET) $(SRC) $(APP_INCLUDE)  $(LIBRARY)


.PHONY : clean
clean :
	@rm -f $(TARGET)