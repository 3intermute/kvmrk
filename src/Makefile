obj-m += kvmrk.o
kvmrk-objs := module.o vectors.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	objdump -d kvmrk.ko > kvmrk.objdump

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insmod:
	sudo dmesg -C
	sudo insmod kvmrk.ko
	sudo dmesg -wH --notime

rmmod:
	sudo rmmod kvmrk.ko
