# The name of the module (must match your C file name, e.g., controlled_thread.c -> controlled_thread.o)
obj-m += pg_dedup.o

# The directory where standard kernel headers are located
KDIR := /lib/modules/$(shell uname -r)/build

# The current directory
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
