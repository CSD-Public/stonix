'''
Created on Sep 17, 2015
Boot security program to turn off wifi, bluetooth, cameras and microphones.
This is most likely called from a job scheduled by the stonix program.

@author: dkennel
'''
def main():
    if os.path.exists('/usr/bin/amixer'):
        setlevels = "/usr/bin/amixer sset Capture Volume 0,0 mute"

    if setlevels != None:
        try:
            proc = subprocess.Popen(setlevels, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, shell=True)
        except Exception:
            pass
        
if __name__ == '__main__':
    pass