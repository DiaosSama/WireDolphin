from PlotCanvas import *


class newinfacewidget(QTableWidget):
    def __init__(self):
        super(newinfacewidget, self).__init__()
        mac = get_cardmac()
        ip4 = get_cardipv4()
        ip6 = get_cardipv6()
        self.inface_dic = union_inface(mac, ip4, ip6)
        self.row = len(self.inface_dic)
        self.list_dic = list(self.inface_dic.keys())
        self.initUI()

    def initUI(self):
        self.setMouseTracking(True)
        self.setRowCount(self.row)
        self.setColumnCount(2)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(30)

        for i in range(self.row):
            newitem1 = QTableWidgetItem(self.list_dic[i])
            self.setItem(i, 0, newitem1)
            self.setRowHeight(i,30)
            #self.setCellWidget(i, 1, PlotCanvas(self, width=4, height=0.1, inface=self.list_dic[i]))
            #self.setItem(i, 1, newitem1)

        self.setSelectionBehavior(QAbstractItemView.SelectRows)  # 整行选择
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 不可编辑

    def mouseMoveEvent(self, event):
        row = self.indexAt(event.pos()).row()
        try:
            name = self.list_dic[row]
            info_inface=name+'\n'+self.inface_dic[name].get_mac()+'\n'+self.inface_dic[name].get_ip4()\
                        +'\n'+self.inface_dic[name].get_ip6()
            QToolTip.showText(QCursor.pos(), info_inface)
        except:
            pass