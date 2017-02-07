#!/usr/bin/python
'''
Created on Jan 5, 2016
@author: dwalker
'''
import re
from subprocess import PIPE, Popen, call


def main():
    check = "/usr/sbin/kextstat "
    proc2 = Popen('/usr/bin/sw_vers -productVersion', shell=True, stdout=PIPE)
    release = proc2.stdout.readline()
    release = release.strip()
    osversion = release
    unload = "/sbin/kextunload "
    filepath = "/System/Library/Extensions/"
    if re.search("^10.11", osversion):
        usb = "IOUSBMassStorageDriver"
    else:
        usb = "IOUSBMassStorageClass"
    cmd = check + "| grep " + usb
    retcode = call(cmd, shell=True)
    if retcode == 0:
        cmd = unload + filepath + usb + ".kext/"
        call(cmd, shell=True)
    fw = "IOFireWireSerialBusProtocolTransport"
    cmd = check + "| grep " + fw
    retcode = call(cmd, shell=True)
    if retcode == 0:
        cmd = unload + filepath + fw + ".kext/"
        call(cmd, shell=True)
    tb = "AppleThunderboltUTDM"
    cmd = check + "| grep " + tb
    retcode = call(cmd, shell=True)
    if retcode == 0:
        cmd = unload + "/System/Library/Extensions/" + tb + ".kext/"
        call(cmd, shell=True)
    sd = "AppleSDXC"
    cmd = check + "| grep " + sd
    retcode = call(cmd, shell=True)
    if retcode:
        cmd = unload + "/System/Library/Extensions/" + sd + ".kext/"
        call(cmd, shell=True)


if __name__ == '__main__':
    main()
