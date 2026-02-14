# 📄 Makefile
obj-m += lsm_hook.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
    sudo insmod lsm_hook.ko

remove:
    sudo rmmod lsm_hook

test:
    sudo dmesg | grep LSM
