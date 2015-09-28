import os
import sys
from time import sleep
from subprocess import Popen, PIPE, call

# PyQt libraries
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *
from PyQt4.QtWebKit import *

from help2_ui import Ui_Help2
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
        self.ui = Ui_Help2()
        self.ui.setupUi(self)
        
        #####
        # Open links to external pages in the default system browser
        self.page = self.ui.webView.page()
        self.page.setLinkDelegationPolicy(QWebPage.DelegateExternalLinks)
        self.connect(self.ui.webView, SIGNAL("linkClicked(QUrl)"), self.openExternal)

        #####
        # Auto load images & disable javascript
        web_settings = self.page.settings()
        # Disabling:
        web_settings.setAttribute(QWebSettings.JavascriptEnabled, False)
        web_settings.setAttribute(QWebSettings.JavaEnabled, False)
        # Enabling for images
        web_settings.setAttribute(QWebSettings.LocalContentCanAccessFileUrls, True)
        web_settings.setAttribute(QWebSettings.LocalStorageEnabled, True)
        web_settings.setAttribute(QWebSettings.PluginsEnabled, True)
        web_settings.setAttribute(QWebSettings.AutoLoadImages, True)
        
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
        # Load index
        self.ui.IndexBrowser.setSource(QUrl("index.html"))

        #####
        # Load ToC
        self.ui.ToCBrowser.setSource(QUrl("toc.html"))

        #############################################################
        #                                                           #
        # Hiding the search bar until search functionality is built #
        #                                                           #
        ###########################################################
        self.ui.search.hide()

        #####
        # Load the intro page
        self.ui.webView.setUrl(QUrl("intro.html"))


    def openExternal(self, url):
        """
        Open external links in the default system browser
        
        @author: Roy Nielsen
        """
        QDesktopServices.openUrl(url)
        
        
    def finish_my_display(self) :
        """
        Reject slot, print a message before sending the reject signal...
        
        Author: Roy Nielsen
        """
        #####
        # Return the app to the initial path.
        os.chdir(self.working_path)
        # print "Done........................................."

        #####
        # Exit the help browser window
        self.done(1)

            
    def onAnchorClicked(self, url):
        """
        When a URL is clicked, open in the extendedBrowser
        
        @author: Roy Nielsen
        """
        self.ui.webView.setUrl(url)
        self.ui.IndexBrowser.setSource(QUrl("index.html"))
        self.ui.ToCBrowser.setSource(QUrl("toc.html"))
        
        
    def goHome(self):
        """
        Send the extendedHelpBrowser to the intro Screen
        
        @author: Roy Nielsen
        """
        self.ui.webView.setUrl(QUrl("intro.html"))
        
        
    def goBack(self):
        """
        Go back one page, if available in history
        
        @author: Roy Nielsen
        """
        self.ui.webView.back()

        
    def goForward(self):
        """
        Go forward one page, if available in history
        
        @author: Roy Nielsen
        """
        self.ui.webView.forward()
        
        
