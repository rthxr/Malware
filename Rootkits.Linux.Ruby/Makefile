obj-m := Ruby.o
CC = gcc -Wall

all:
	$(MAKE) -C /lib/modules/`uname -r`/build M=`pwd` modules

clean:
	$(MAKE) -C /lib/modules/`uname -r`/build M=`pwd` clean
