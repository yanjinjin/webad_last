#obj-$(CONFIG_WEBAD) += webad.o
#webad-y := nf_conntrack_webad.o

obj-m := webad.o
webad-objs := nf_conntrack_webad.o
KERNELDIR :=/lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all:
	make -C $(KERNELDIR) M=$(PWD) modules
clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	-rm -f config.h
