SUBDIRS = src

EXTRA_DIST = \
	COPYING.LGPL \
	ChangeLog \
	DESIGN

if MAINTAINER_MODE
ChangeLog: .hg/dirstate
	hg log --style=changelog > ChangeLog
endif
