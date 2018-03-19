# contrib/postgres_fdw/Makefile

MODULE_big = planscape
OBJS = planscape.o report.o hook_engine.o hde/hde64.o pg_hooks.o json.o symboliser.o
PGFILEDESC = ""

PG_CPPFLAGS = -I$(libpq_srcdir)
SHLIB_LINK = $(libpq)

EXTENSION = planscape

REGRESS = planscape

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

CFLAGS_CXX_SAFE := $(shell echo "${CFLAGS}" | sed \
                     -e s/-Wdeclaration-after-statement// \
                     -e s/-Wmissing-prototypes// \
                     -e s/-fexcess-precision=standard//)

override CXXFLAGS += ${CFLAGS_CXX_SAFE} -fvisibility=hidden -fvisibility-inlines-hidden -O0
override CFLAGS += -fvisibility=hidden -Wno-declaration-after-statement
SHLIB_LINK = -lstdc++ -lcurl
