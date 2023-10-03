AM_CPPFLAGS = \
        -I${linux_headers} \
        -I$(top_srcdir)/src/libstrongswan \
        -I$(top_srcdir)/src/libcharon

AM_CFLAGS = $(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-doca.la
else
plugin_LTLIBRARIES = libstrongswan-doca.la
endif

libstrongswan_doca_la_SOURCES = \
        doca_plugin.c \
        doca_plugin.h \
        doca_plugin_ipsec.c \
        doca_plugin_ipsec.h

libstrongswan_doca_la_LDFLAGS =  -module -avoid-version
libstrongswan_doca_la_LIBADD = $(DLLIB)
