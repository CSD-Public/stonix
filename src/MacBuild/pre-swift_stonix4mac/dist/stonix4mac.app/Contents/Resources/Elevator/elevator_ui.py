# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'elevator.ui'
#
# Created by: PyQt5 UI code generator 5.6
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_Elevator(object):
    def setupUi(self, Elevator):
        Elevator.setObjectName("Elevator")
        Elevator.resize(366, 170)
        self.gridLayout = QtWidgets.QGridLayout(Elevator)
        self.gridLayout.setObjectName("gridLayout")
        self.label = QtWidgets.QLabel(Elevator)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(16)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 4)
        self.label_2 = QtWidgets.QLabel(Elevator)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.label_2.sizePolicy().hasHeightForWidth())
        self.label_2.setSizePolicy(sizePolicy)
        self.label_2.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 1, 0, 1, 1)
        self.adminName = QtWidgets.QLineEdit(Elevator)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.adminName.sizePolicy().hasHeightForWidth())
        self.adminName.setSizePolicy(sizePolicy)
        self.adminName.setObjectName("adminName")
        self.gridLayout.addWidget(self.adminName, 1, 1, 1, 3)
        self.label_3 = QtWidgets.QLabel(Elevator)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(1)
        sizePolicy.setHeightForWidth(self.label_3.sizePolicy().hasHeightForWidth())
        self.label_3.setSizePolicy(sizePolicy)
        self.label_3.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label_3.setObjectName("label_3")
        self.gridLayout.addWidget(self.label_3, 2, 0, 1, 1)
        self.passwordLineEdit = QtWidgets.QLineEdit(Elevator)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.passwordLineEdit.sizePolicy().hasHeightForWidth())
        self.passwordLineEdit.setSizePolicy(sizePolicy)
        self.passwordLineEdit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.passwordLineEdit.setObjectName("passwordLineEdit")
        self.gridLayout.addWidget(self.passwordLineEdit, 2, 1, 1, 3)
        spacerItem = QtWidgets.QSpacerItem(158, 17, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.gridLayout.addItem(spacerItem, 3, 0, 1, 2)
        self.cancelButton = QtWidgets.QPushButton(Elevator)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.cancelButton.sizePolicy().hasHeightForWidth())
        self.cancelButton.setSizePolicy(sizePolicy)
        self.cancelButton.setAutoDefault(False)
        self.cancelButton.setObjectName("cancelButton")
        self.gridLayout.addWidget(self.cancelButton, 3, 2, 1, 1)
        self.authUserButton = QtWidgets.QPushButton(Elevator)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.MinimumExpanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.authUserButton.sizePolicy().hasHeightForWidth())
        self.authUserButton.setSizePolicy(sizePolicy)
        self.authUserButton.setDefault(True)
        self.authUserButton.setObjectName("authUserButton")
        self.gridLayout.addWidget(self.authUserButton, 3, 3, 1, 1)

        self.retranslateUi(Elevator)
        QtCore.QMetaObject.connectSlotsByName(Elevator)

    def retranslateUi(self, Elevator):
        _translate = QtCore.QCoreApplication.translate
        Elevator.setWindowTitle(_translate("Elevator", "Administrator Credentials Required"))
        self.label.setText(_translate("Elevator", "Please enter administrator credentials for: "))
        self.label_2.setText(_translate("Elevator", "Name: "))
        self.label_3.setText(_translate("Elevator", "Password:"))
        self.cancelButton.setText(_translate("Elevator", "Cancel"))
        self.authUserButton.setText(_translate("Elevator", "Ok"))

