# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'admin_credentials.ui'
#
# Created: Tue Nov  3 14:49:47 2015
#      by: PyQt4 UI code generator 4.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

class Ui_AdministratorCredentials(object):
    def setupUi(self, AdministratorCredentials):
        AdministratorCredentials.setObjectName(_fromUtf8("AdministratorCredentials"))
        AdministratorCredentials.resize(366, 170)
        self.gridLayout = QtGui.QGridLayout(AdministratorCredentials)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.label = QtGui.QLabel(AdministratorCredentials)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(16)
        self.label.setFont(font)
        self.label.setObjectName(_fromUtf8("label"))
        self.gridLayout.addWidget(self.label, 0, 0, 1, 4)
        self.label_2 = QtGui.QLabel(AdministratorCredentials)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.label_2.sizePolicy().hasHeightForWidth())
        self.label_2.setSizePolicy(sizePolicy)
        self.label_2.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label_2.setObjectName(_fromUtf8("label_2"))
        self.gridLayout.addWidget(self.label_2, 1, 0, 1, 1)
        self.adminName = QtGui.QLineEdit(AdministratorCredentials)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.adminName.sizePolicy().hasHeightForWidth())
        self.adminName.setSizePolicy(sizePolicy)
        self.adminName.setObjectName(_fromUtf8("adminName"))
        self.gridLayout.addWidget(self.adminName, 1, 1, 1, 3)
        self.label_3 = QtGui.QLabel(AdministratorCredentials)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.label_3.sizePolicy().hasHeightForWidth())
        self.label_3.setSizePolicy(sizePolicy)
        self.label_3.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label_3.setObjectName(_fromUtf8("label_3"))
        self.gridLayout.addWidget(self.label_3, 2, 0, 1, 1)
        self.passwordLineEdit = QtGui.QLineEdit(AdministratorCredentials)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.passwordLineEdit.sizePolicy().hasHeightForWidth())
        self.passwordLineEdit.setSizePolicy(sizePolicy)
        self.passwordLineEdit.setEchoMode(QtGui.QLineEdit.Password)
        self.passwordLineEdit.setObjectName(_fromUtf8("passwordLineEdit"))
        self.gridLayout.addWidget(self.passwordLineEdit, 2, 1, 1, 3)
        spacerItem = QtGui.QSpacerItem(158, 17, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem, 3, 0, 1, 2)
        self.cancelButton = QtGui.QPushButton(AdministratorCredentials)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cancelButton.sizePolicy().hasHeightForWidth())
        self.cancelButton.setSizePolicy(sizePolicy)
        self.cancelButton.setAutoDefault(False)
        self.cancelButton.setObjectName(_fromUtf8("cancelButton"))
        self.gridLayout.addWidget(self.cancelButton, 3, 2, 1, 1)
        self.authUserButton = QtGui.QPushButton(AdministratorCredentials)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.authUserButton.sizePolicy().hasHeightForWidth())
        self.authUserButton.setSizePolicy(sizePolicy)
        self.authUserButton.setDefault(True)
        self.authUserButton.setObjectName(_fromUtf8("authUserButton"))
        self.gridLayout.addWidget(self.authUserButton, 3, 3, 1, 1)

        self.retranslateUi(AdministratorCredentials)
        QtCore.QMetaObject.connectSlotsByName(AdministratorCredentials)

    def retranslateUi(self, AdministratorCredentials):
        AdministratorCredentials.setWindowTitle(_translate("AdministratorCredentials", "Administrator Credentials Required", None))
        self.label.setText(_translate("AdministratorCredentials", "Please enter administrator credentials for: ", None))
        self.label_2.setText(_translate("AdministratorCredentials", "Name: ", None))
        self.label_3.setText(_translate("AdministratorCredentials", "Password:", None))
        self.cancelButton.setText(_translate("AdministratorCredentials", "Cancel", None))
        self.authUserButton.setText(_translate("AdministratorCredentials", "Ok", None))

