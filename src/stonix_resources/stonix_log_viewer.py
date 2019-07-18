# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'stonix_log_viewer.ui'
#
# Created: Tue Jul 16 13:22:16 2019
#      by: PyQt4 UI code generator 4.10.1
#

import os

# compatibility between pyqt4 and pyqt5
try:
    from PyQt5 import QtCore, QtGui
    from PyQt5.QtWidgets import QWidget, QSizePolicy, QApplication,\
        QDialog, QVBoxLayout, QHBoxLayout, QTextBrowser, QTextEdit,\
        QLabel, QPushButton, QLayout
    from PyQt5.QtCore.QMetaType import QString, QVariant
except:
    from PyQt4 import QtCore, QtGui
    from PyQt4.QtGui import QWidget, QSizePolicy, QApplication, \
        QDialog, QVBoxLayout, QHBoxLayout, QTextBrowser, QTextEdit, \
        QLabel, QPushButton, QLayout
    from PyQt4.QtCore import QString, QVariant
from .environment import Environment

try:
    _fromUtf8 = QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QApplication.translate(context, text, disambig)

class Ui_log_viewer_window(QDialog):
    """
    stonix log viewer class
    creates a log viewer window for displaying and searching the last run log
    """

    def __init__(self, parent=None):
        """
        set up the stonix log viewer window gui element

        :return:
        """

        # we need environment to dynamically get the path to the icons
        self.env = Environment()
        self.icon_path = self.env.get_icon_path()
        cancel_button_icon = os.path.join(self.icon_path, "cancel_48.png")
        search_button_icon = os.path.join(self.icon_path, "system-search.png")

        # Create the window
        QDialog.__init__(self, parent)

        self.setObjectName(_fromUtf8("log_viewer_window"))
        self.resize(805, 600)
        self.setMinimumSize(QtCore.QSize(805, 600))
        self.setBaseSize(QtCore.QSize(805, 600))
        self.log_central_widget = QWidget()
        sizePolicy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.log_central_widget.sizePolicy().hasHeightForWidth())
        self.log_central_widget.setSizePolicy(sizePolicy)
        self.log_central_widget.setObjectName(_fromUtf8("log_central_widget"))
        self.verticalLayoutWidget = QWidget(self.log_central_widget)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(10, 20, 800, 600))
        self.verticalLayoutWidget.setObjectName(_fromUtf8("verticalLayoutWidget"))
        hbox = QHBoxLayout()
        #hbox.addStretch(1)
        self.log_viewer_layout = QVBoxLayout()
        self.log_viewer_layout.setSpacing(-1)
        self.log_viewer_layout.setSizeConstraint(QLayout.SetDefaultConstraint)
        self.log_viewer_layout.setContentsMargins(5, 5, 5, 10)
        self.log_viewer_layout.setObjectName(_fromUtf8("log_viewer_layout"))
        self.log_display_browser = QTextBrowser(self.verticalLayoutWidget)
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.log_display_browser.sizePolicy().hasHeightForWidth())
        self.log_display_browser.setSizePolicy(sizePolicy)
        self.log_display_browser.setMinimumSize(QtCore.QSize(800, 450))
        self.log_display_browser.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.log_display_browser.setBaseSize(QtCore.QSize(800, 450))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.log_display_browser.setFont(font)
        self.log_display_browser.viewport().setProperty("cursor", QtGui.QCursor(QtCore.Qt.IBeamCursor))
        self.log_display_browser.setFocusPolicy(QtCore.Qt.ClickFocus)
        self.log_display_browser.setAcceptDrops(False)
        self.log_display_browser.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.log_display_browser.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.log_display_browser.setObjectName(_fromUtf8("log_display_browser"))
        self.log_viewer_layout.addWidget(self.log_display_browser)
        self.log_search_text = QTextEdit(self.verticalLayoutWidget)
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.log_search_text.sizePolicy().hasHeightForWidth())
        self.log_search_text.setSizePolicy(sizePolicy)
        self.log_search_text.setMinimumSize(QtCore.QSize(0, 30))
        self.log_search_text.setMaximumSize(QtCore.QSize(16777215, 30))
        self.log_search_text.setBaseSize(QtCore.QSize(800, 30))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.log_search_text.setFont(font)
        self.log_search_text.viewport().setProperty("cursor", QtGui.QCursor(QtCore.Qt.IBeamCursor))
        self.log_search_text.setFocusPolicy(QtCore.Qt.ClickFocus)
        self.log_search_text.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.log_search_text.setReadOnly(False)
        self.log_search_text.setObjectName(_fromUtf8("log_search_text"))

        self.log_viewer_layout.addWidget(self.log_search_text)
        self.log_search_button = QPushButton(self.verticalLayoutWidget)
        sizePolicy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.log_search_button.sizePolicy().hasHeightForWidth())
        self.log_search_button.setSizePolicy(sizePolicy)
        self.log_search_button.setMinimumSize(QtCore.QSize(0, 30))
        self.log_search_button.setBaseSize(QtCore.QSize(0, 30))
        self.log_search_button.setFocusPolicy(QtCore.Qt.TabFocus)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(_fromUtf8(search_button_icon)), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.log_search_button.setIcon(icon)
        self.log_search_button.setObjectName(_fromUtf8("log_search_button"))
        self.log_viewer_layout.addWidget(self.log_search_button)
        # compatibility between pyqt4 and pyqt5
        try:
            QtCore.QObject.connect(self.log_search_button, QtCore.SIGNAL('clicked()'), self.highlight_search_results)
        except:
            self.log_search_button.clicked.connect(self.highlight_search_results)
        self.log_search_results_label = QLabel(self.verticalLayoutWidget)
        sizePolicy = QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.log_search_results_label.sizePolicy().hasHeightForWidth())
        sizePolicy.setHorizontalPolicy(QSizePolicy.Expanding)
        self.log_search_results_label.setSizePolicy(sizePolicy)
        self.log_search_results_label.setMargin(5)
        self.log_search_results_label.setMinimumSize(QtCore.QSize(250, 30))
        self.log_search_results_label.setBaseSize(QtCore.QSize(250, 30))
        self.log_search_results_label.setFocusPolicy(QtCore.Qt.NoFocus)
        self.log_search_results_label.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.log_search_results_label.setObjectName(_fromUtf8("log_search_results_label"))
        hbox.addWidget(self.log_search_results_label)
        self.log_close_button = QPushButton(self.verticalLayoutWidget)
        sizePolicy = QSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.log_close_button.sizePolicy().hasHeightForWidth())
        self.log_close_button.setSizePolicy(sizePolicy)
        self.log_close_button.setMinimumSize(QtCore.QSize(80, 30))
        self.log_close_button.setBaseSize(QtCore.QSize(80, 30))
        self.log_close_button.setFocusPolicy(QtCore.Qt.TabFocus)
        self.log_close_button.setLayoutDirection(QtCore.Qt.RightToLeft)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(_fromUtf8(cancel_button_icon)), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.log_close_button.setIcon(icon1)
        self.log_close_button.setObjectName(_fromUtf8("log_close_button"))
        hbox.addWidget(self.log_close_button)
        # compatibility between pyqt4 and pyqt5
        try:
            QtCore.QObject.connect(self.log_close_button, QtCore.SIGNAL('clicked()'), self.close)
        except:
            self.log_close_button.clicked.connect(self.close)
        self.log_viewer_layout.addLayout(hbox)
        self.setLayout(self.log_viewer_layout)
        self.retranslateUi()

        # set default focus to search field
        # Note that 0-millisecond QTimer objects will be replaced by QThreads in the future (not in pyqt5)
        QtCore.QTimer.singleShot(0, self.log_search_text.setFocus)

        # doesn't appear to be needed and doesn't appear to do anything when enabled
        #QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        """
        set names and shortcuts for log viewer window

        :return:
        """

        self.setWindowTitle(_translate("log_viewer_window", "Log Viewer", None))
        self.log_search_button.setText(_translate("log_viewer_window", "Search", None))
        self.log_search_button.setShortcut(_translate("log_viewer_window", "Ctrl+S", None))
        self.log_close_button.setText(_translate("log_viewer_window", "Close", None))
        self.log_close_button.setShortcut(_translate("log_viewer_window", "Esc", None))

    def highlight_search_results(self):
        """
        search through log output and highlight all matching search terms

        """

        # get search field text and set up cursor
        searchterm = self.log_search_text.toPlainText()
        cursor = self.log_display_browser.textCursor()
        cursor.select(QtGui.QTextCursor.Document)
        cursor.setCharFormat(QtGui.QTextCharFormat())

        # clear all highlighted items for each new search
        cursor.clearSelection()
        self.log_display_browser.moveCursor(QtGui.QTextCursor.End)

        # reset search results for each new search
        self.search_results = []

        # search through log_display and highlight all matching search terms
        while self.log_display_browser.find(searchterm, QtGui.QTextDocument.FindBackward):
            result = self.log_display_browser.ExtraSelection()

            highlighter = QtGui.QColor(QtCore.Qt.yellow).lighter(160)

            result.format.setBackground(highlighter)
            result.format.setProperty(QtGui.QTextFormat.FullWidthSelection, QVariant(True))
            result.cursor = self.log_display_browser.textCursor()
            result.cursor.clearSelection()
            self.search_results.append(result)

        self.log_display_browser.setExtraSelections(self.search_results)
        num_results = str(len(self.search_results))
        self.log_search_results_label.setText("Search Results: " + num_results)

    def display_log_text(self, text):
        """Display the submitted text in the log_display.

        :param text: text to display in log window

        """

        if type(text) is list:
            temptext = ''
            for line in text:
                temptext = temptext + line
            text = temptext
        self.log_display_browser.setPlainText(text)
