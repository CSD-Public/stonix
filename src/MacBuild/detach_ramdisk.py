#!/usr/bin/python
###############################################################################
#                                                                             #
# Copyright 2015.  Los Alamos National Security, LLC. This material was       #
# produced under U.S. Government contract DE-AC52-06NA25396 for Los Alamos    #
# National Laboratory (LANL), which is operated by Los Alamos National        #
# Security, LLC for the U.S. Department of Energy. The U.S. Government has    #
# rights to use, reproduce, and distribute this software.  NEITHER THE        #
# GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY, LLC MAKES ANY WARRANTY,        #
# EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.  #
# If software is modified to produce derivative works, such modified software #
# should be clearly marked, so as not to confuse it with the version          #
# available from LANL.                                                        #
#                                                                             #
# Additionally, this program is free software; you can redistribute it and/or #
# modify it under the terms of the GNU General Public License as published by #
# the Free Software Foundation; either version 2 of the License, or (at your  #
# option) any later version. Accordingly, this program is distributed in the  #
# hope that it will be useful, but WITHOUT ANY WARRANTY; without even the     #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    #
# See the GNU General Public License for more details.                        #
#                                                                             #
###############################################################################
"""
@author: Roy Nielsen
"""
from macRamdisk import detach
from log_message import log_message
from optparse import OptionParser, SUPPRESS_HELP

parser = OptionParser(usage="\n\n%prog [options]\n\n", version="0.7.2")

parser.add_option("-D", "--detach", dest="device", default="",
                  help="Name of the device to detach")
parser.add_option("-d", "--debug", action="store_true", dest="debug", 
                  default=0, help="Print debug messages")
parser.add_option("-v", "--verbose", action="store_true", 
                  dest="verbose", default=0, 
                  help="Print status messages")

(opts, args) = parser.parse_args()

if opts.verbose != 0:
    message_level = "verbose"
elif opts.debug != 0:
    message_level = "debug"
else:
    message_level="normal"

if opts.device == 0:
    raise Exception("Cannot detach a device with no name..")
else:
    device = opts.device
    
if detach(device, message_level):
    log_message(r"Successfully detached disk: " + str(device).strip(), "verbose", message_level)
else:
    log_message(r"Couldn't detach disk: " + str(device).strip())

