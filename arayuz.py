from PyQt5.QtWidgets import QTableWidgetItem
import sqlite3
import silme
import threading, paketyakalama


from PyQt5 import QtCore, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(1024, 768)
        self.pushButton = QtWidgets.QPushButton(Form)
        self.pushButton.setGeometry(QtCore.QRect(20, 20, 190, 50))
        self.pushButton.setObjectName("pushButton")




        self.pushButton_2 = QtWidgets.QPushButton(Form)
        self.pushButton_2.setGeometry(QtCore.QRect(220, 20, 190, 50))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(Form)
        self.pushButton_3.setGeometry(QtCore.QRect(810, 20, 190, 50))

        self.pushButton_3.setObjectName("pushButton_3")
        self.comboBox = QtWidgets.QComboBox(Form)
        self.comboBox.setGeometry(QtCore.QRect(420, 20, 380, 50))
        self.comboBox.setObjectName("comboBox")
        self.tableWidget = QtWidgets.QTableWidget(Form)
        self.tableWidget.setGeometry(QtCore.QRect(20, 90, 984, 658))
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(6)
        self.tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()




        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

        self.pushButton.clicked.connect(self.get_data)
        self.pushButton_2.clicked.connect(self.sil)
        self.pushButton_3.clicked.connect(self.get_combo)

        self.comboBox.addItem("Hepsi")
        self.comboBox.addItem("(UDP)")
        self.comboBox.addItem("(TCP)")
        self.comboBox.addItem("(IGMP)")

    def sil(self):
        silme.sil()
        self.get_data()



    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Ağ Üzerindeki Veri Paketlerinin Yaklanması ve Analizi"))
        self.pushButton.setText(_translate("Form", "Yenile"))
        self.pushButton_2.setText(_translate("Form", "Sıfırla"))
        self.pushButton_3.setText(_translate("Form", "Filtrele"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("Form", "No"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("Form", "source"))
        item = self.tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("Form", "Destination"))
        item = self.tableWidget.horizontalHeaderItem(3)
        item.setText(_translate("Form", "Protocol"))
        item = self.tableWidget.horizontalHeaderItem(4)
        item.setText(_translate("Form", "Lengt"))
        item = self.tableWidget.horizontalHeaderItem(5)
        item.setText(_translate("Form", "İnfo"))







    def get_data(self):

        db= sqlite3.connect("veritabani.db")
        cursor=db.cursor()
        command = ''' SELECT * from veri '''
        results= cursor.execute(command)
        self.tableWidget.setRowCount(0)
        for row_number, row_data in enumerate(results):
            self.tableWidget.insertRow(row_number)
            for column_number, data in enumerate(row_data):
                self.tableWidget.setItem(row_number, column_number, QTableWidgetItem(str(data)))

    def get_combo(self):
        x = self.comboBox.currentText()
        if (x == "(TCP)"):
            db = sqlite3.connect("veritabani.db")
            cursor = db.cursor()
            results = db.execute("SELECT * FROM veri WHERE protocol = '(TCP)'")

            self.tableWidget.setRowCount(0)
            for row_number, row_data in enumerate(results):
                self.tableWidget.insertRow(row_number)
                for column_number, data in enumerate(row_data):
                    self.tableWidget.setItem(row_number, column_number, QTableWidgetItem(str(data)))
        elif (x == "(UDP)"):
            db = sqlite3.connect("veritabani.db")
            cursor = db.cursor()
            results = db.execute("SELECT * FROM veri WHERE protocol = '(UDP)'")

            self.tableWidget.setRowCount(0)
            for row_number, row_data in enumerate(results):
                self.tableWidget.insertRow(row_number)
                for column_number, data in enumerate(row_data):
                    self.tableWidget.setItem(row_number, column_number, QTableWidgetItem(str(data)))
        elif (x == "(IGMP)"):
            db = sqlite3.connect("veritabani.db")
            cursor = db.cursor()
            results = db.execute("SELECT * FROM veri WHERE protocol = '(IGMP)'")

            self.tableWidget.setRowCount(0)
            for row_number, row_data in enumerate(results):
                self.tableWidget.insertRow(row_number)
                for column_number, data in enumerate(row_data):
                    self.tableWidget.setItem(row_number, column_number, QTableWidgetItem(str(data)))
        elif (x == "Hepsi"):
            db = sqlite3.connect("veritabani.db")
            cursor = db.cursor()
            results = db.execute("SELECT * FROM veri")

            self.tableWidget.setRowCount(0)
            for row_number, row_data in enumerate(results):
                self.tableWidget.insertRow(row_number)
                for column_number, data in enumerate(row_data):
                    self.tableWidget.setItem(row_number, column_number, QTableWidgetItem(str(data)))


def aaa():
    import sys
    app = QtWidgets.QApplication(sys.argv)
    form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(form)
    form.show()
    sys.exit(app.exec_())


t1 = threading.Thread(target=aaa)
t1.start()
