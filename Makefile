
# Set the path to the Kernel build utils.
KBUILD:=/lib/modules/$(shell uname -r)/build/

#menuconfig:
#	$(MAKE) -C $(KBUILD) M=$(PWD) menuconfig

CFLAGS_xtun-srv.o += -Wfatal-errors
CFLAGS_xtun-srv.o += -Werror
CFLAGS_xtun-srv.o += -Wno-declaration-after-statement
CFLAGS_xtun-srv.o += -Wno-error=unused-function
CFLAGS_xtun-srv.o += -mpopcnt

CFLAGS_xtun-clt.o += -Wfatal-errors
CFLAGS_xtun-clt.o += -Werror
CFLAGS_xtun-clt.o += -Wno-declaration-after-statement
CFLAGS_xtun-clt.o += -Wno-error=unused-function
CFLAGS_xtun-clt.o += -mpopcnt

obj-m += xtun-srv.o
obj-m += xtun-clt.o

default:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean
