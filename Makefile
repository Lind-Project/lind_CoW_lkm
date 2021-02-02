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
