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
Class to manage a dialog to warn if the app is not on /dev/disk2

Date originated: 4/26/2013
Author: Roy Nielsen
"""
# PyQt libraries
#from PyQt4.QtCore import SIGNAL
#from PyQt4.QtGui import QDialog

from PyQt5 import QtCore, QtGui, QtWidgets

# local app libraries
from general_warning_ui import Ui_GeneralWarning

from log_message import log_message 

class GeneralWarning(QtWidgets.QDialog) :
    """
    Class to manage the dialog to get the property number
    
    Author: Roy Nielsen
    """
    def __init__(self, parent=None) :
        """
        Initialization method
        
        Author: Roy Nielsen
        """
        super(GeneralWarning, self).__init__(parent)
        self.ui = Ui_GeneralWarning()

        self.message_level = "debug"
        self.ui.setupUi(self)
        self.ui.buttonBox.accepted(self.accept)
        #self.connect(self.ui.buttonBox, SIGNAL("accepted()"), self.accept)

        log_message("Finished initializing NotOnCorrectDisk Class...", "debug", self.message_level)


    def setWarningMessage(self, message="") :
        """
        Set the warning message label
        
        Author: Roy Nielsen
        """
        self.ui.label.setText(message)

    """
    def setWindowTitle(self, title="") :
        ""
        Set the window title for the warning
        
        Author: Roy Nielsen
        ""
        self.setWindowTitle(_fromUtf8(str(title)))
    """
    def setOpenExternalLinks(self) :
        """
        Set the window to open external web links
        
        Author: Roy Nielsen
        """
        self.ui.label.setOpenExternalLinks(True)

        