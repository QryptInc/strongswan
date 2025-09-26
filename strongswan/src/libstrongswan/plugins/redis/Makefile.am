AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-redis.la
else
plugin_LTLIBRARIES = libstrongswan-redis.la
endif

libstrongswan_redis_la_SOURCES = \
	redis_plugin.h redis_plugin.c redis.c redis.h

libstrongswan_redis_la_LDFLAGS = -module -avoid-version
libstrongswan_redis_la_LIBADD  = -lhiredis
