
# Set the path to the Kernel build utils.
KBUILD:=/lib/modules/$(shell uname -r)/build/

#menuconfig:
#   $(MAKE) -C $(KBUILD) M=$(PWD) menuconfig

CFLAGS_srv.o += -Wfatal-errors
CFLAGS_srv.o += -Werror
CFLAGS_srv.o += -Wno-declaration-after-statement
CFLAGS_srv.o += -Wno-error=unused-function
CFLAGS_srv.o += -mpopcnt

CFLAGS_clt.o += -Wfatal-errors
CFLAGS_clt.o += -Werror
CFLAGS_clt.o += -Wno-declaration-after-statement
CFLAGS_clt.o += -Wno-error=unused-function
CFLAGS_clt.o += -mpopcnt

obj-m += srv.o
obj-m += clt.o

default:
	$(MAKE) -C $(KBUILD) M=$(PWD) modules

clean:
	$(MAKE) -C $(KBUILD) M=$(PWD) clean
