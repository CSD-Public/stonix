#!/usr/bin/env python3
"""
@author: Roy Nielsen
"""

#--- Native python libraries
import sys
from optparse import OptionParser, SUPPRESS_HELP
sys.path.append("..")
#--- non-native python libraries in this source tree
from macRamdisk import detach
from lib.loggers import CyLogger
from lib.loggers import LogPriority as lp

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
    level = CyLogger(level=lp.INFO)
elif opts.debug != 0:
    level = CyLogger(level=lp.DEBUG)
else:
    level=lp.WARNING

if opts.device == 0:
    raise Exception("Cannot detach a device with no name..")
else:
    device = opts.device
    
logger = CyLogger(level=level)
logger.initializeLogs()
    
if detach(device, logger):
    logger.log(lp.INFO, r"Successfully detached disk: " + str(device).strip())
else:
    logger.log(lp.WARNING, r"Couldn't detach disk: " + str(device).strip())
    raise Exception(r"Cannot eject disk: " + str(device).strip())

