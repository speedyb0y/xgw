
# Set the path to the Kernel build utils.
KBUILD=/lib/modules/$(shell uname -r)/build/

#menuconfig:
#	$(MAKE) -C $(KBUILD) M=$(PWD) menuconfig

CFLAGS_xvlan.o := -Wfatal-errors
CFLAGS_xvlan.o := -Werror
CFLAGS_xvlan.o := -Wno-declaration-after-statement

obj-m += xtun.o

default:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean
