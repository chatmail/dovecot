#!/usr/bin/python

'''Dovecot Apport interface

Copyright (C) 2010 Canonical Ltd/
Author: Chuck Short <chuck.short@canonical.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''

from apport.hookutils import *

def add_info(report, ui):
   response = ui.yesno("The output of dovecot -n may help developers diagnose your bug more quickly, however, it may contain sensitive information. Do you want to include it in your bug report?")

   if response == None: #user canceled
       raise StopIteration

   elif response == True:
       report['DovecotConf'] = root_command_output(['/usr/sbin/dovecot', '-n'])


   elif response == False:
       ui.information("The contents of dovecot -n will NOT be includeded in the bug report")

   packages=['dovecot-common', 'dovecot-core', 'dovecot-dev', 'dovecot-pop3d', 'dovecot-imapd',  'mail-stack-delivery', 'dovecot-postfix']
   versions = ''
   for package in packages:
       try:
           version  = package.get_version(package)
       except:
           version = 'N/A'
       versions += '%s %s\n' %(package, version)
   report['DovecotInstalledVersions'] = versions

