CLEANFILES = *~
MAINTAINERCLEANFILES = $(MANS) README

#EXTRA_DIST = README $(MANS) $(XMLS) tst-pam_chksshpwd
EXTRA_DIST = README $(MANS) $(XMLS)

man_MANS = pam_chksshpwd.8
XMLS = README.xml pam_chksshpwd.8.xml

#TESTS = tst-pam_chksshpwd

securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = -I$(top_srcdir)/libpam/include -I$(top_srcdir)/libpamc/include
AM_LDFLAGS = -no-undefined -avoid-version -module
if HAVE_VERSIONING
  AM_LDFLAGS += -Wl,--version-script=$(srcdir)/../modules.map
endif

securelib_LTLIBRARIES = pam_chksshpwd.la
pam_chksshpwd_la_LIBADD = $(top_builddir)/libpam/libpam.la @LIBCRYPT@

if ENABLE_REGENERATE_MAN
noinst_DATA = README
README: pam_chksshpwd.8.xml
-include $(top_srcdir)/Make.xml.rules
endif
