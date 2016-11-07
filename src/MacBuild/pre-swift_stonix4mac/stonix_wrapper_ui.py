# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'stonix4mac/stonix_wrapper.ui'
#
# Created by: PyQt5 UI code generator 5.6
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_StonixWrapper(object):
    def setupUi(self, StonixWrapper):
        StonixWrapper.setObjectName("StonixWrapper")
        StonixWrapper.resize(371, 134)
        self.gridLayout = QtWidgets.QGridLayout(StonixWrapper)
        self.gridLayout.setObjectName("gridLayout")
        self.label_2 = QtWidgets.QLabel(StonixWrapper)
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setWordWrap(True)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 1, 0, 1, 1)
        self.label = QtWidgets.QLabel(StonixWrapper)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setWordWrap(True)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 1, 1, 1, 1)
        self.userButton = QtWidgets.QPushButton(StonixWrapper)
        self.userButton.setObjectName("userButton")
        self.gridLayout.addWidget(self.userButton, 2, 0, 1, 1)
        self.adminButton = QtWidgets.QPushButton(StonixWrapper)
        self.adminButton.setObjectName("adminButton")
        self.gridLayout.addWidget(self.adminButton, 2, 1, 1, 1)
        self.quitButton = QtWidgets.QPushButton(StonixWrapper)
        self.quitButton.setObjectName("quitButton")
        self.gridLayout.addWidget(self.quitButton, 2, 2, 1, 1)
        self.label_3 = QtWidgets.QLabel(StonixWrapper)
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.label_3.setObjectName("label_3")
        self.gridLayout.addWidget(self.label_3, 0, 0, 1, 3)

        self.retranslateUi(StonixWrapper)
        QtCore.QMetaObject.connectSlotsByName(StonixWrapper)

    def retranslateUi(self, StonixWrapper):
        _translate = QtCore.QCoreApplication.translate
        StonixWrapper.setWindowTitle(_translate("StonixWrapper", "Stonix4Mac"))
        self.label_2.setText(_translate("StonixWrapper", "Run as normal User"))
        self.label.setText(_translate("StonixWrapper", "Run as an Admin"))
        self.userButton.setStatusTip(_translate("StonixWrapper", "Run as a normal User"))
        self.userButton.setWhatsThis(_translate("StonixWrapper", "Run as a normal User"))
        self.userButton.setText(_translate("StonixWrapper", "User"))
        self.adminButton.setToolTip(_translate("StonixWrapper", "Run as an Admin User"))
        self.adminButton.setWhatsThis(_translate("StonixWrapper", "Run as an Admin User"))
        self.adminButton.setText(_translate("StonixWrapper", "Admin"))
        self.quitButton.setText(_translate("StonixWrapper", "Quit"))
        self.label_3.setText(_translate("StonixWrapper", "Stonix for Mac"))

