#--- Native python libraries
import os
import sys
import ctypes

def getLibc():
    """
    Acquire a reference to the system libc, initially to access the
    filesystem "sync" function.

    @returns: python reference to the C libc object, or False, if it can't
              find libc on the system.

    @author: Roy Nielsen
    @change: 2018/02/27 bgonz12 - added "/lib64/libc.so.6" to possible_paths
    """
    osFamily = sys.platform.lower().strip()
    #print "---==## OS Family: " + str(osFamily) + " #==---"

    if osFamily and  osFamily.startswith("darwin"):
        #####
        # For Mac
        try:
            #temp_dir = sys._MEIPASS
            #libc_path = os.path.join(temp_dir, "libc.dylib")
            #libc = ctypes.CDLL("libSystem.dylib")
            libc = ctypes.CDLL("/usr/lib/libc.dylib")
        except:
            raise Exception("DAMN IT JIM!!!")
        else:
            print "Loading Mac dylib......................................"
    elif osFamily and  osFamily.startswith("linux"):
        #####
        # For Linux
        possible_paths = ["/lib/x86_64-linux-gnu/libc.so.6",
                          "/lib/i386-linux-gnu/libc.so.6",
                          "/lib64/libc.so.6",
                          "/usr/lib64/libc.so.6"]
        for path in possible_paths:

            if os.path.exists(path):
                libc = ctypes.CDLL(path)
                #print "     Found libc!!!"
                break
    else:
        libc = False
    try:
        if libc:
            libc.sync()
            #print":::::Syncing..............."
    except:
        raise Exception("..............................Cannot Sync.")

    #print "OS Family: " + str(osFamily)

    return libc
