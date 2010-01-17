#!/bin/sh
#
# To make expire-tool working some failing plugins have to be removed
# from MAIL_PLUGINS environment variable.
# (see: http://wiki.dovecot.org/Plugins/Expire)
#
# This script must be installed as /usr/lib/dovecot/expire-tool.sh

MAIL_PLUGINS=${MAIL_PLUGINS//imap_quota/}
MAIL_PLUGINS=${MAIL_PLUGINS//mail_log/} 

exec ${0%.sh} "$@"
