#

_CUSTOM_SUBDIRS_ = \
    stk500

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/stk500/stk500.la
