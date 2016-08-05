# ramdisk
Interface to use, eventually for cross-platform setup and maintenance of ramdisk, primarily for unittesting and compiling code.

Initial work done only for the Mac platform.

## NOTE:
The code has two branches, master (hopefully stable) and develop (not necessarily stable).  The goal is to only merge to develop when functionality is stable and tests have been written for that functionality.

###Mac

Instanciating the RamDisk class will create a ramdisk that you can use - in chunks of 1Mb.

Initial work done only for the Mac platform.


###Linux

Ramdisk class that can use either current method for creating a ramdisk on Linux, currently working on a tmpfs version....

##Future work:

###Windows

Will call a currently available binary to create a ramdisk.


## Languages

Currently written/tested in only python v2.7

Future plans to duplicate in other languages as well.

