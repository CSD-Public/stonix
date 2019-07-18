#!/usr/bin/python
from . import ramdisk
from .ramdisk.lib.loggers import CyLogger

from . import buildlib

logdispatch = ramdisk.lib.loggers.CyLogger(debug_mode=True)

logdispatch.initializeLogs()

print(str(logdispatch))

testlib = buildlib.MacBuildLib(logdispatch)

testlib.changeViewControllerTitle("stonix4mac 1001")


 
