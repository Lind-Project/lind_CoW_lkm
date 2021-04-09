obj-m += cow.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}
 
all:
	 make -C /lib/modules/$(shell uname -r)/build/ M=$(shell pwd) modules

debug:
	 make -C /lib/modules/$(shell uname -r)/build/ M=$(shell pwd) modules 
	 EXTRA_CFLAGS="$(MY_CFLAGS)"
clean:
	 make -C /lib/modules/$(shell uname -r)/build/ M=$(shell pwd) clean

utest: utest.c
	 gcc utest.c -o utest
test: utest all
	 -rmmod cow.ko 
	 insmod cow.ko
	 ./utest
stest: utest.c all
	 gcc utest.c -o ustest -DTESTSWAP=1
	 -rmmod cow.ko 
	 insmod cow.ko
	 ./ustest

fuzz: fuzz.c all
	 gcc fuzz.c -o fuzz
	 -rmmod cow.ko 
	 insmod cow.ko
	 ./fuzz
