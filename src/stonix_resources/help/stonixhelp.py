#!/usr/bin/python

import sys

#####
# import PyQt libraries
from PyQt4.QtGui import QApplication

from help import Help

if __name__ == "__main__" :
    """
    Main program

    Author: Roy Nielsen
    """

    app = QApplication(sys.argv)
    
    myhelp = Help()
    myhelp.show()
    myhelp.raise_()
    
    app.exec_()    
