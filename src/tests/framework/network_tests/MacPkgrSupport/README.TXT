If Luggage is installed on a mac, all one has to do
to build a package is 

$ sudo make pkg

and the package will be created.

This package installs test files on the filesystem 
from both the installer and the postinstall scripts.  
This is for testing the MacPkgr class in Stonix.

For testing installed files, postflight created files,
and proper removal of installed files(not postinstall
script created files).

