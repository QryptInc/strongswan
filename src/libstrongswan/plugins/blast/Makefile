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
    -L./\
	-lQryptSecurityC  \
	-lQryptSecurity   \
	-lstrongswan      \
	-lcharon

blast.so: blast_ke.c blast_plugin.c
	$(CC) -fPIC -c blast_ke.c -o blast_ke.o $(CFLAGS)
	$(CC) -fPIC -c blast_plugin.c -o blast_plugin.o  $(CFLAGS)
	gcc -shared -o $@ blast_ke.o blast_plugin.o $(LDFLAGS)

install: blast.so blast.conf
	cp blast.so $(SWANPLUGINS)/libstrongswan-blast.so
	cp blast.conf $(PLUGINCONF)

install-deps:
	cp libQryptSecurity.so libQryptSecurityC.so $(DEPSDIR)

clean:
	rm -f *.so *.o

.PHONY: clean install