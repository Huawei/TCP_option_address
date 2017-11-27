#
# Makefile for the IPVS TOA  modules on top of IPv4.
#

obj-$(CONFIG_TOA) += toa.o

default:
	make CONFIG_TOA=m  -C /lib/modules/`uname -r`/build M=`pwd` modules

debug:
	make CONFIG_TOA=m  -C /lib/modules/`uname -r`/build M=`pwd` modules EXTRA_CFLAGS="-DTOA_DBG_MSG"
clean:
	rm -f .*.cmd *.o *.ko *.mod.c modules.order Module.symvers
	rm -rf .tmp_versions
install:
	test -d "$(DESTDIR)/lib/modules/`uname -r`/extra/net/toa" \
		|| mkdir -p "$(DESTDIR)/lib/modules/`uname -r`/extra/net/toa"
	cp *.ko  "$(DESTDIR)/lib/modules/`uname -r`/extra/net/toa"
