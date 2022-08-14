NAME	        := net_pf_device
obj-m           := $(NAME).o
KDIR		?= /lib/modules/$(shell uname -r)/build


$(NAME)-y	:= driver_main.o \
		   txrx_net_packet_filter.o

ccflags-y	:= -std=gnu99 -O2


all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -rf *~
