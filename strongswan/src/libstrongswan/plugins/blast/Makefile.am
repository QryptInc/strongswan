AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-blast.la
else
plugin_LTLIBRARIES = libstrongswan-blast.la
endif

libstrongswan_blast_la_SOURCES = \
	blast_plugin.h blast_plugin.c blast_ke.c blast_ke.h

libstrongswan_blast_la_LDFLAGS = -module -avoid-version
libstrongswan_blast_la_LIBADD  = -lQryptSecurityC
