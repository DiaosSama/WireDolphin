from PyQt5.QtGui import QCursor, QColor
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QAbstractItemView, QToolTip, QApplication, QWidget, \
    QHBoxLayout
from pathlib import Path
import sys

class pcapqtablewidget(QTableWidget):
    def __init__(self):
        super(pcapqtablewidget, self).__init__()
        self.initUI()

    def initUI(self):
        self.lastRowBkColor = QColor(0x00, 0xff, 0x00, 0x00)
        self.previousColorRow = 0
        self.setMouseTracking(True)
        self.setColumnCount(2)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(15)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)  # 整行选择
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 不可编辑

    def leaveEvent(self, event):
        item = self.item(self.previousColorRow, 0)
        if item != 0:
            try:
                self.setRowColor(self.previousColorRow, self.lastRowBkColor)
            except:
                pass

    def setRowColor(self, row, color):
        for i in range(self.columnCount()):
            self.item(row, i).setBackground(color)

    def mouseMoveEvent(self, event):
        try:
            row = self.indexAt(event.pos()).row()
            column = self.indexAt(event.pos()).column()
            try:
                QToolTip.showText(QCursor.pos(), self.item(row, column).text())
            except:
                pass
            item = self.item(self.previousColorRow, 0)
            try:
                if item != 0:
                    self.setRowColor(self.previousColorRow, self.lastRowBkColor)
                item = self.item(row, column)
                if item != 0 and item.isSelected() != True:
                    self.setRowColor(row, QColor(193, 210, 240))
                self.previousColorRow = row
            except:
                pass
        except:
            pass
        else:
            pass
            #self.enterEvent(row, column)

class Table(QWidget):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setMouseTracking(True)
        self.setWindowTitle("QTableWidget测试")
        self.resize(720, 480)
        conLayout = QHBoxLayout()
        tableWidget = pcapqtablewidget()
        for i in range(20):
            correct_row = tableWidget.rowCount()
            tableWidget.insertRow(correct_row)
            newItem = QTableWidgetItem(str(i))
            tableWidget.setItem(i, 0, newItem)

        conLayout.addWidget(tableWidget)
        tableWidget.setStyleSheet("selection-background-color:red")

        self.setLayout(conLayout)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    example = Table()
    example.show()
    sys.exit(app.exec())