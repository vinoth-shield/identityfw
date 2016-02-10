#
#  Copyright (C) 2015-2018 www.shield.com - All Rights Reserved.
#  Shield UTM/NGFW [http://www.shield.com]
#  You are granted a non-exclusive License to use the Shield UTM/NGFW
#  software for any purposes for an unlimited period of time. The software
#  product under this License is provided free of charge.
#  Even though a license fee is not paid for the use of Freeware Version
#  software, it does not mean that there are no conditions for using such
#  software:
#
#   1. The Software may be installed and used by the Licensee for any legal
#      purpose.
#
#   2. The Software may be installed and used by the Licensee on any number
#      of systems.
#
#   3. The Software can be copied and distributed under the condition that
#      original copyright notice and disclaimer of warranty will stay intact,
#      and the Licensee will not charge money or fees for the Software
#      product, except to cover distribution costs.
#
#   4. The Licensee will not have any proprietary rights in and to the
#      Software. The Licensee acknowledges and agrees that the Licensor retains
#      all copyrights and other proprietary rights in and to the Software.
#
#   5. Use within the scope of this License is free of charge and no royalty
#      or licensing fees shall be paid by the Licensee.
#

KDIR :=  ${KERNELSRC}
PWD := $(shell pwd)

obj-m := src/identityfw.o

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

install:
	mkdir -p ${ROOT}/lib/custom_modules/
	cp src/identityfw.ko ${ROOT}/lib/custom_modules/
