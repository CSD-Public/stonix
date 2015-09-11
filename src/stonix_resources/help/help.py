import os
import sys
from time import sleep
from subprocess import Popen, PIPE, call

# PyQt libraries
from PyQt4.QtCore import *
from PyQt4.QtGui import *

from help2_ui import Ui_HelpDialog2
from turtle import Screen

try:
    _fromUtf8 = QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

class Help(QDialog):
    """
    Mock class for initially intended for Stonix help..
    
    @author: Roy Nielsen
    """
    def __init__(self, parent=None) :
        """
        Initialization method
        
        @author: Roy Nielsen
        """
        super(Help, self).__init__(parent)
        self.ui = Ui_HelpDialog2()
        self.ui.setupUi(self)
        
        #####
        # get the current path
        self.working_path = os.getcwd()
        
        #####
        # Change to the app's help directory
        dir_path = os.path.dirname(os.path.abspath(__file__))
        os.chdir(dir_path)

        #####
        # Set up signals and slots
        self.ui.okButton.clicked.connect(self.finish_my_display)

        #####
        # What to do with links clicked on in the ToC and Index.
        self.ui.IndexBrowser.anchorClicked.connect(self.onAnchorClicked)
        self.ui.ToCBrowser.anchorClicked.connect(self.onAnchorClicked)

        #####
        # signals/slots for home, back and forward buttons
        self.ui.homeButton.clicked.connect(self.goHome)
        self.ui.backButton.clicked.connect(self.goBack)
        self.ui.forwardButton.clicked.connect(self.goForward)

        #####
        # Load icons
        icon = QIcon()
        icon.addPixmap(QPixmap(_fromUtf8("house_2.ico")), QIcon.Normal, QIcon.Off)
        self.ui.homeButton.setIcon(icon)
        self.ui.homeButton.setIconSize(QSize(24, 24))

        icon1 = QIcon()
        icon1.addPixmap(QPixmap(_fromUtf8("left.ico")), QIcon.Normal, QIcon.Off)
        self.ui.backButton.setIcon(icon1)
        self.ui.backButton.setIconSize(QSize(24, 24))
        
        icon2 = QIcon()
        icon2.addPixmap(QPixmap(_fromUtf8("right.ico")), QIcon.Normal, QIcon.Off)
        self.ui.forwardButton.setIcon(icon2)
        self.ui.forwardButton.setIconSize(QSize(24, 24))

        #####
        # Load index
        self.ui.IndexBrowser.setSource(QUrl("index.html"))

        #####
        # Load ToC
        self.ui.ToCBrowser.setSource(QUrl("toc.html"))
        
        #####
        # Set to open external links
        self.ui.extendedHelpBrowser.setOpenExternalLinks(True)
        
    def finish_my_display(self) :
        """
        Reject slot, print a message before sending the reject signal...
        
        Author: Roy Nielsen
        """
        #####
        # Return the app to the initial path.
        os.chdir(self.working_path)
        print "Done........................................."

        #####
        # Exit the help browser window
        self.done(1)

            
    def onAnchorClicked(self, url):
        """
        When a URL is clicked, open in the extendedBrowser
        
        @author: Roy Nielsen
        """
        self.ui.extendedHelpBrowser.setSource(url)
        self.ui.IndexBrowser.setSource(QUrl("index.html"))
        self.ui.ToCBrowser.setSource(QUrl("toc.html"))
        
        
    def goHome(self):
        """
        Send the extendedHelpBrowser to the intro Screen
        
        @author: Roy Nielsen
        """
        self.ui.extendedHelpBrowser.setSource(QUrl("intro.html"))
        
        
    def goBack(self):
        """
        Go back one page, if available in history
        
        @author: Roy Nielsen
        """
        self.ui.extendedHelpBrowser.backward()

        
    def goForward(self):
        """
        Go forward one page, if available in history
        
        @author: Roy Nielsen
        """
        self.ui.extendedHelpBrowser.forward()
        
        