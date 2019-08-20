#!/usr/bin/env python3
'''
Created on Sep 17, 2015
Boot security program to turn off wifi, bluetooth, cameras and microphones.
This is most likely called from a job scheduled by the stonix program.

This is the linux variant of this program and it will soft disable Wifi,
Bluetooth and Microphones. There is not a good way to soft disable the camera
in Linux.

@author: dkennel
@version: 1.0
'''

import subprocess
import os


def main():
    setlevels = None
    if os.path.exists('/usr/bin/amixer'):
        setlevels = "/usr/bin/amixer sset Capture Volume 0,0 mute"

    if setlevels != None:
        try:
            proc = subprocess.Popen(setlevels, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=True)
        except Exception:
            pass

    netmgr = None
    if os.path.exists('/usr/bin/nmcli'):
        netmgr = '/usr/bin/nmcli nm wifi off'
    if netmgr != None:
        try:
            proc = subprocess.Popen(netmgr, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=True)
        except Exception:
            pass

    rfkill = None
    if os.path.exists('/usr/sbin/rfkill'):
        netmgr = '/usr/sbin/rfkill block bluetooth'
    if rfkill != None:
        try:
            proc = subprocess.Popen(rfkill, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=True)
        except Exception:
            pass

if __name__ == '__main__':
    main()
