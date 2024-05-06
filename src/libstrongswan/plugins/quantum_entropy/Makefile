# The following variables may be changed on the make command line:
#
# the directory to the strongSwan sources
SWANDIR?=~/git/strongswan
# location of config.h
CONFIGH?=$(SWANDIR)/config.h
# default install prefix
PREFIX?=/usr/local
# location of the installed strongSwan libraries
SWANLIBS?=$(PREFIX)/lib/ipsec
# location of the strongSwan plugins
SWANPLUGINS?=$(PREFIX)/lib/ipsec/plugins
# target location of the plugin config snippet
PLUGINCONF?=/usr/local/etc/strongswan.d/charon/

DEPSDIR?=/usr/local/lib/

CFLAGS=-O2 -Wall -fpic                 \
		-include $(CONFIGH)            \
		-I$(SWANDIR)/src/libstrongswan \
		-I$(SWANDIR)/src/libcharon     \
		-include $(SWANDIR)/src/libstrongswan/plugins/plugin.h \
		-include $(SWANDIR)/src/libstrongswan/library.h

LDFLAGS=-L$(SWANLIBS) \
	-lstrongswan      \
	-lcharon          \
	-ljansson

quantum_entropy.so: quantum_entropy_rng.c quantum_entropy_plugin.c base64.c
	$(CC) -fPIC -c quantum_entropy_rng.c -o quantum_entropy_rng.o $(CFLAGS)
	$(CC) -fPIC -c quantum_entropy_plugin.c -o quantum_entropy_plugin.o  $(CFLAGS)
	$(CC) -fPIC -c base64.c -o base64.o  $(CFLAGS)
	gcc -shared -o $@ quantum_entropy_rng.o quantum_entropy_plugin.o base64.o $(LDFLAGS)

install: quantum_entropy.so quantum_entropy.conf
	cp quantum_entropy.so $(SWANPLUGINS)/libstrongswan-quantum_entropy.so
	cp quantum_entropy.conf $(PLUGINCONF)

clean:
	rm -f *.so *.o

.PHONY: clean install