import _thread
import threading
import sys
import os
import json
from PyQt5 import sip
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.uic.properties import QtGui
from PyQt5.QtGui import QPalette, QPixmap, QFont
from PyQt5.QtCore import Qt
from Capture import *

from selector import *

from pathlib import Path

from pcapqtablewidget import *

from pic_UI import *

from newinfacewidget import *


class Packet_information(QWidget):
    """
    数据分组显示界面，包括分组展开和16进制展开
    """

    def __init__(self, pkt, hexpac):
        super().__init__()
        self.initUI(pkt, hexpac)

    def initUI(self, pkt, hexpac):
        """
        双击数据包界面初始化
        :param pkt: 分组信息
        :param hexpac: 分组信息的字符串
        :return: None
        """
        # 设置窗口图标
        self.setWindowIcon(QIcon('img_source/dolphin.ico'))
        # 初始主窗口字体
        self.font = QFont()
        with open('data_source/font.json', 'r') as file_obj:
            '''读取json文件'''
            old_font = json.load(file_obj)
        if old_font["font"]:
            self.font.setFamily(old_font["font"])
            self.font.setPointSize(int(old_font["size"]))
        else:
            self.font.setFamily("Consolas")
            old_font["font"] = "Consolas"
            self.font.setPointSize(11)
            with open('data_source/font.json', 'w') as file_obj:
                '''写入json文件'''
                json.dump(old_font, file_obj)

        # 显示包的十六进制的QTextEdit
        self.pac_hexnew = QTextEdit()
        self.pac_hexnew.setReadOnly(True)  # 不可编辑
        self.pac_hexnew.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.pac_hexnew.setFont(self.font)
        self.pac_hexnew.setPlainText(hexpac)
        self.pac_hexnew.setFont(self.font)
        # self.pac_hexnew.setFixedWidth(1250)
        # self.pac_hexnew.setFixedHeight(350)

        self.setWindowTitle("数据包信息")
        self.setFixedSize(1280, 720)
        self.info_pack = QTreeWidget()
        self.info_pack.clear()
        # self.info_pack.setFixedHeight(350)
        # self.info_pack.setFixedWidth(1250)
        # 设置字体
        self.info_pack.setFont(self.font)
        # 设置列数
        self.info_pack.setColumnCount(1)
        # 隐藏表头
        self.info_pack.header().hide()

        self.info_pack.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.read_layer(pkt)

        conLayout = QVBoxLayout()
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.info_pack)
        splitter.addWidget(self.pac_hexnew)
        # conLayout.addWidget(self.info_pack)
        # conLayout.addWidget(self.pac_hexnew)
        conLayout.addWidget(splitter)
        self.setLayout(conLayout)

    def read_layer(self, layer):
        """
        用来将分组按层展开并显示
        :param layer: 记录分组展开的列表
        :return: None
        """
        length = len(layer)
        if length == 0:
            return
        item1 = QTreeWidgetItem(self.info_pack)
        for i in range(length):
            if i == length - 1:
                if isinstance(layer[i], list):
                    self.read_layer(layer[i])
                else:
                    QTreeWidgetItem(item1).setText(0, str(layer[i]))
            elif isinstance(layer[i], list):
                self.read_layer(layer[i])
            elif i == 0:
                item1.setText(0, str(layer[i]))
            else:
                QTreeWidgetItem(item1).setText(0, str(layer[i]))


class Wiredolphin(QMainWindow):
    """
    Wiredolphin的主窗口，用来展示整个程序
    """

    def __init__(self, parent=None):
        """
        初始化整个界面的框架，包括菜单栏、导航栏、状态栏等
        :param parent: None
        """
        self.ui_id = 1
        # 初始主窗口字体
        self.font = QFont()
        with open('data_source/font.json', 'r') as file_obj:
            '''读取json文件'''
            old_font = json.load(file_obj)  # 返回列表数据，也支持字典
        self.font.setFamily(old_font["font"])
        self.font.setPointSize(old_font["size"])

        self.default_inface = "WLAN"
        self.sni = Capture(self.default_inface)
        super(Wiredolphin, self).__init__(parent)
        # 设计窗口的图标
        winicon = QIcon()
        winicon.addPixmap(QPixmap("img_source/dolphin.ico"), QIcon.Normal, QIcon.Off)
        self.setWindowIcon(winicon)
        self.setIconSize(QSize(20, 20))
        self.setWindowTitle("wiredolphin")
        # self.setFixedSize(1920, 1080)  # 固定大小不可变
        # self.resize(1920,1080)
        self.setObjectName("MainWindow")
        self.setStyleSheet("#MainWindow{background-color: white}")

        bar = self.menuBar()
        file1 = bar.addMenu("文件(F)")
        file2 = bar.addMenu("编辑(E)")
        file3 = bar.addMenu("视图(V)")
        file4 = bar.addMenu("统计(S)")

        self.open = QAction("打开(O)", self)
        self.open.setShortcut("Ctrl+O")
        self.save = QAction("保存(S)", self)
        self.save.setShortcut("Ctrl+S")
        self.close = QAction("关闭(C)", self)
        self.close.setShortcut("Ctrl+W")
        self.btn_font = QAction("字体设置(Ctrl+Shift+F)", self)
        self.btn_font.setShortcut("Ctrl+Shift+F")
        self.view1 = QAction("分组列表(L)", self)
        self.view1.setCheckable(True)
        self.view1.setChecked(True)
        self.view1.setShortcut("(L)")
        self.view2 = QAction("分组详情(D)", self)
        self.view2.setCheckable(True)
        self.view2.setChecked(True)
        self.view2.setShortcut("(D)")
        self.view3 = QAction("分组字节流(B)", self)
        self.view3.setCheckable(True)
        self.view3.setChecked(True)
        self.view3.setShortcut("(B)")
        self.statics = QAction("协议统计")
        self.tree_no = QAction("No")
        self.tree_no.setCheckable(True)
        self.tree_no.setChecked(True)
        self.tree_time = QAction("Time")
        self.tree_time.setCheckable(True)
        self.tree_time.setChecked(True)
        self.tree_source = QAction("Source")
        self.tree_source.setCheckable(True)
        self.tree_source.setChecked(True)
        self.tree_destination = QAction("Destination")
        self.tree_destination.setCheckable(True)
        self.tree_destination.setChecked(True)
        self.tree_protocol = QAction("Protocol")
        self.tree_protocol.setCheckable(True)
        self.tree_protocol.setChecked(True)
        self.tree_length = QAction("Length")
        self.tree_length.setCheckable(True)
        self.tree_length.setChecked(True)
        self.tree_info = QAction("Info")
        self.tree_info.setCheckable(True)
        self.tree_info.setChecked(True)

        file1.addAction(self.open)
        file1.addAction(self.save)
        file1.addAction(self.close)
        file2.addAction(self.btn_font)
        file3.addAction(self.view1)
        file3.addAction(self.view2)
        file3.addAction(self.view3)
        file3.addSeparator()
        file3.addAction(self.tree_no)
        file3.addAction(self.tree_time)
        file3.addAction(self.tree_source)
        file3.addAction(self.tree_destination)
        file3.addAction(self.tree_protocol)
        file3.addAction(self.tree_length)
        file3.addAction(self.tree_info)
        file4.addAction(self.statics)

        # 开始捕获按键
        tb = self.addToolBar("File")
        icon_start = QIcon()
        icon_start.addPixmap(QPixmap("img_source/start.png"), QIcon.Normal, QIcon.Off)
        self.start = QAction(self)
        self.start.setToolTip("开始捕获分组")
        self.start.setIcon(icon_start)
        self.start.setText("Start")
        tb.addAction(self.start)

        # 停止捕获按键
        icon_pause = QIcon()
        icon_pause.addPixmap(QPixmap("img_source/pause.jpg"), QIcon.Normal, QIcon.Off)
        self.pause = QAction(self)
        self.pause.setToolTip("暂停捕获分组")
        self.pause.setIcon(icon_pause)
        self.pause.setText("Pause")
        tb.addAction(self.pause)

        # 暂停捕获按键
        icon_stop = QIcon()
        icon_stop.addPixmap(QPixmap("img_source/stop.png"), QIcon.Normal, QIcon.Off)
        self.stop = QAction(self)
        self.stop.setToolTip("停止捕获分组")
        self.stop.setIcon(icon_stop)
        self.stop.setText("Stop")
        tb.addAction(self.stop)

        # 重新开始捕获
        icon_restart = QIcon()
        icon_restart.addPixmap(QPixmap("img_source/restart.png"), QIcon.Normal, QIcon.Off)
        self.restart = QAction(self)
        self.restart.setToolTip("重新开始当前捕获")
        self.restart.setIcon(icon_restart)
        self.restart.setText("Restart")
        tb.addAction(self.restart)

        self.open.triggered.connect(self.openMsg)
        self.save.triggered.connect(self.savepcap)
        self.close.triggered.connect(self.closeEvent)

        self.btn_font.triggered.connect(self.UI_font)
        self.view1.triggered.connect(self.UI_layout)
        self.view2.triggered.connect(self.UI_layout)
        self.view3.triggered.connect(self.UI_layout)
        self.tree_no.triggered.connect(self.info_tree_check)
        self.tree_time.triggered.connect(self.info_tree_check)
        self.tree_source.triggered.connect(self.info_tree_check)
        self.tree_destination.triggered.connect(self.info_tree_check)
        self.tree_protocol.triggered.connect(self.info_tree_check)
        self.tree_length.triggered.connect(self.info_tree_check)
        self.tree_info.triggered.connect(self.info_tree_check)

        self.statics.triggered.connect(self.statistics)

        self.start.triggered.connect(self.startsniff)
        self.pause.triggered.connect(self.pausesniff)
        self.stop.triggered.connect(self.stopsniff)
        self.restart.triggered.connect(self.restartsniff)

        # 底部状态栏
        self.statusBar = QStatusBar()
        self.statusBar.setStyleSheet("background-color:#F5F5F5")
        self.setStatusBar(self.statusBar)
        self.packet_total = QLabel('无分组')
        self.packet_show = QLabel('不显示')
        self.helloinfo = QLabel('欢迎使用wiredolphin')
        self.statusBar.addPermanentWidget(self.helloinfo, stretch=2)
        self.statusBar.addPermanentWidget(self.packet_total, stretch=1)
        self.statusBar.addPermanentWidget(self.packet_show, stretch=1)
        self.center_win()
        self.startwireshark()

        '''最近打开文件的路径'''

    def UI_font(self):
        """
        界面字体的选择编辑
        :return: None
        """
        font, ok = QFontDialog.getFont()
        if ok:
            with open('data_source/font.json', 'r') as file_obj:
                '''读取json文件'''
                old_font = json.load(file_obj)  # 返回列表数据，也支持字典
            old_font["font"] = font.family()
            old_font["size"] = font.pointSize()
            with open('data_source/font.json', 'w') as file:
                json.dump(old_font, file)
            self.font = font
            if self.ui_id == 1:
                self.pac_path.setFont(self.font)
                self.inface_info.setFont(self.font)
            elif self.ui_id == 2 or self.ui_id == 3:
                self.info_treeWidget.setFont(self.font)
                self.info_pack.setFont(self.font)
                self.pac_hexnew.setFont(self.font)

    def startwireshark(self):
        """
        初始化开始界面：分别有两个表格，一个记录最近打开的pcap，一个用于网卡信息显示
        :return: None
        """
        # 刷新底部信息栏
        self.ui_id = 1
        self.refresh()
        self.setWindowTitle("wiredolphin")
        # 三个按钮的状态
        self.start.setEnabled(True)
        self.pause.setEnabled(False)
        self.restart.setEnabled(False)
        self.stop.setEnabled(False)

        self.open.setEnabled(True)
        self.close.setEnabled(False)
        self.save.setEnabled(False)

        self.view1.setDisabled(True)
        self.view2.setDisabled(True)
        self.view3.setDisabled(True)
        self.tree_no.setDisabled(True)
        self.tree_time.setDisabled(True)
        self.tree_source.setDisabled(True)
        self.tree_destination.setDisabled(True)
        self.tree_protocol.setDisabled(True)
        self.tree_length.setDisabled(True)
        self.tree_info.setDisabled(True)

        self.statics.setDisabled(True)
        # 定义了一个新窗口
        centralwidget = QWidget(self)

        # 获取屏幕的尺寸用于初始化布局
        screen = QDesktopWidget().screenGeometry()

        # 定义一个标签
        label_hello = QLabel("欢迎使用Wiredolphin")
        label_hello.setStyleSheet('border-width:1px;border-style:solid;border-color:rgb(255, 170, '
                                  '0);background-color:rgb(100,149,237);border-radius:10;')
        label_hello.setFixedHeight(screen.height() / 25)
        label_hello.setFixedWidth(screen.width() / 8)
        label_hello.setFont(self.font)

        '''显示曾经打开过的文件目录'''
        self.pac_path = pcapqtablewidget()
        self.pac_path.setFont(self.font)
        self.pac_path.setFrameShape(QFrame.NoFrame)
        self.pac_path.setFixedWidth(screen.width() / 1.5)
        self.pac_path.setColumnCount(2)
        self.pac_path.setColumnWidth(0, screen.width() / 1.75)
        self.pac_path.setColumnWidth(1, screen.width() / 19.2)
        self.pac_path.setFixedHeight(screen.height() / 3.5)
        # self.pac_path.horizontalHeader().setDefaultSectionSize(1280)
        self.latest_pcap()
        self.pac_path.doubleClicked.connect(self.openpcap)

        '''显示电脑网卡信息和流量信息'''
        self.inface_info = newinfacewidget()
        self.inface_info.setFont(self.font)
        # inface_info.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.inface_info.setFrameShape(QFrame.NoFrame)
        self.inface_info.setFixedWidth(screen.width() / 1.5)
        self.inface_info.setFixedHeight(screen.height() / 3.5)
        self.inface_info.setColumnWidth(0, screen.width() / 8)
        self.inface_info.setColumnWidth(1, screen.width() / 2)

        '''将控件装载入布局'''
        widget_layout = QHBoxLayout()
        start_mainlayout = QVBoxLayout()
        start_mainlayout.addWidget(label_hello)
        start_mainlayout.addWidget(self.pac_path, 0, Qt.AlignHCenter)
        start_mainlayout.addWidget(self.inface_info, 0, Qt.AlignHCenter)
        widget_layout.addStretch()
        widget_layout.addLayout(start_mainlayout)
        widget_layout.addStretch()
        centralwidget.setLayout(widget_layout)
        self.setCentralWidget(centralwidget)
        self.inface_info.doubleClicked.connect(self.select_inface)
        self.time_plot = QTimer(self)
        self.time_plot.timeout.connect(self.add_plot)
        self.time_plot.start(100)
        # self.add_plot()

    def add_plot(self):
        """
        页面内再加载流量曲线图
        :return: None
        """
        self.time_plot.stop()
        for i in range(self.inface_info.row):
            self.inface_info.setCellWidget(i, 1,
                                           PlotCanvas(self, width=4, height=0.1, inface=self.inface_info.list_dic[i]))

    def latest_pcap(self):
        """
        装载最近打开的文件，加入布局
        :return: None
        """
        filename = "data_source/pathfile.txt"
        try:
            f = open(filename, 'r', encoding="utf-8")
        except IOError:
            # print("open %s error!\n" % filename)
            pass
        else:
            line = f.readline()
            text = []
            while line:
                if Path(line.strip("\n")).exists():
                    text.append(line.strip("\n"))
                else:
                    pass
                line = f.readline()
            for i in range(len(text)):
                correct_row = self.pac_path.rowCount()
                self.pac_path.insertRow(correct_row)
                newItem = QTableWidgetItem(text[i])
                self.pac_path.setItem(i, 0, newItem)
                newItem = QTableWidgetItem(self.format_file(os.path.getsize(text[i])))
                self.pac_path.setItem(i, 1, newItem)
                self.pac_path.setRowHeight(i, 30)

    def format_file(self, file_byte):
        """
        格式化文件大小
        :param file_byte: 字节数
        :return: 已经格式化的字节数(字符串str)
        """
        file_byte = float(file_byte)
        if file_byte > 1024 * 1024 * 1024:
            return str(round(file_byte / (1024 * 1024 * 1024), 2)) + "GB"
        elif file_byte > 1024 * 1024:
            return str(round(file_byte / (1024 * 1024), 2)) + "MB"
        elif file_byte > 1024:
            return str(round(file_byte / (1024), 2)) + "KB"
        else:
            return str(file_byte) + "B"

    def open_latest_pacp(self, newfile):
        """
        打开文件更新txt
        :param newfile: 存储最近打开路径信息的文件名
        :return: None
        """
        filename = "data_source/pathfile.txt"
        try:
            f = open(filename, 'r', encoding="utf-8")
        except IOError:
            pass
            # print("open %s error!\n" % filename)
        else:
            line = f.readline()
            text = []
            while line:
                if Path(line.strip("\n")).exists():
                    text.append(line.strip("\n"))
                else:
                    pass
                line = f.readline()
            if newfile in text:
                text.remove(newfile)
            text.insert(0, newfile)
            try:
                f = open(filename, 'w', encoding="utf-8")
            except IOError:
                # print("open %s error!\n" % filename)
                pass
            else:
                for i in range(len(text)):
                    f.write(text[i] + "\n")
                f.close()

    def openpcap(self, item):
        """
        双击打开pcap文件的函数
        :param item: 表格中的对象
        :return:
        """
        try:
            row = item.row()
            filename = self.pac_path.item(row, 0).text()
            self.sni = Capture("WLAN")
            if self.sni.load_pcap(filename):
                self.open_latest_pacp(filename)
                self.load_pcap()
            else:
                reply = QMessageBox.critical(self, "错误", "无法打开该文件", QMessageBox.Close)
                if reply == QMessageBox.Close:
                    return
        except:
            pass

    def select_inface(self, item):
        """
        选择网卡进行抓包，同时调用监听数据包的界面的函数
        :param item: 表格中的对象
        :return: None
        """
        row = item.row()
        self.default_inface = self.inface_info.list_dic[row]
        self.setWindowTitle(self.default_inface)
        self.startsniff()

    def refresh(self, newlen=0):
        """
        刷新底部状态栏
        :param newlen: 已经捕获的分组的长度
        :return: None
        """
        if self.ui_id == 1:
            self.packet_total.setText("无分组")
            self.packet_show.setText("不显示")
        elif self.ui_id == 2:
            self.packet_total.setText("分组：" + str(newlen))
            self.packet_show.setText("已显示：" + str(self.treepack))
        elif self.ui_id == 3:
            self.packet_total.setText("分组：" + str(newlen))
            self.packet_show.setText("已显示：" + str(self.treepack))

    def load_pcap(self):
        """
        加载pcap数据包生成的界面
        :return: None
        """
        self.ui_id = 3
        # 三个按钮的状态
        self.start.setEnabled(False)
        self.pause.setEnabled(False)
        self.restart.setEnabled(False)
        self.stop.setEnabled(False)

        self.open.setEnabled(False)
        self.close.setEnabled(True)
        self.save.setEnabled(False)

        self.view1.setEnabled(True)
        self.view2.setEnabled(True)
        self.view3.setEnabled(True)
        self.tree_no.setEnabled(True)
        self.tree_time.setEnabled(True)
        self.tree_source.setEnabled(True)
        self.tree_destination.setEnabled(True)
        self.tree_protocol.setEnabled(True)
        self.tree_length.setEnabled(True)
        self.tree_info.setEnabled(True)

        self.statics.setEnabled(True)
        # 定义了一个新窗口
        centralwidget_forever = QWidget(self)
        layout = QVBoxLayout()

        # 定义一个过滤器输入框
        self.filter_edit = QLineEdit()
        self.filter_edit.setMaximumWidth(1890)
        self.filter_edit.setMinimumWidth(690)
        self.filter_edit.setFixedHeight(20)
        self.filter_edit.returnPressed.connect(self.filter_test)
        self.filter_edit.setPlaceholderText("输入过滤规则")

        self.info_pack = QTreeWidget()
        self.info_pack.clear()
        # self.info_pack.setFixedHeight(440)
        # self.info_pack.setFixedWidth(1890)
        # 设置字体
        self.info_pack.setFont(self.font)
        # 设置列数
        self.info_pack.setColumnCount(1)
        # 隐藏表头
        self.info_pack.header().hide()

        self.info_pack.setFrameStyle(QFrame.Box | QFrame.Plain)

        # 显示基础包的信息的表格
        self.info_treeWidget = QTreeWidget()
        self.info_treeWidget.setColumnCount(7)
        self.info_treeWidget.setHeaderLabels(['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        # self.info_treeWidget.header().hide() #表头隐藏
        self.info_treeWidget.setSelectionMode(QTreeWidget.SingleSelection)  # 设置只能选中一行
        self.info_treeWidget.setSelectionBehavior(QTreeWidget.SelectRows)  # 整行选择
        self.info_treeWidget.setAutoScroll(True)  # 自动滚动
        self.info_treeWidget.setFrameStyle(QFrame.Box | QFrame.Plain)
        # self.info_treeWidget.setFixedWidth(1890)
        # self.info_treeWidget.setFixedHeight(440)

        self.info_treeWidget.setFont(self.font)

        self.info_treeWidget.setColumnWidth(0, 100)
        self.info_treeWidget.setColumnWidth(1, 150)
        self.info_treeWidget.setColumnWidth(2, 200)
        self.info_treeWidget.setColumnWidth(3, 200)
        self.info_treeWidget.setColumnWidth(4, 130)
        self.info_treeWidget.setColumnWidth(5, 130)
        self.info_treeWidget.setColumnWidth(5, 130)
        self.info_treeWidget.setColumnWidth(6, 950)
        self.info_treeWidget.setStyleSheet("selection-background-color:blue")

        # 显示包的十六进制的QTextEdit
        self.pac_hexnew = QTextEdit()
        self.pac_hexnew.setReadOnly(True)  # 不可编辑
        self.pac_hexnew.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.pac_hexnew.setFont(self.font)

        # 将控件加入布局中
        layout.addWidget(self.filter_edit)
        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.addWidget(self.info_treeWidget)
        self.splitter.addWidget(self.info_pack)
        self.splitter.addWidget(self.pac_hexnew)
        # layout.addWidget(self.info_treeWidget)
        # layout.addWidget(self.info_pack)
        layout.addWidget(self.splitter)
        centralwidget_forever.setLayout(layout)
        self.setCentralWidget(centralwidget_forever)
        sni_start = threading.Thread(target=self.filter_test, daemon=True)
        sni_start.start()

        # 连接点击事件到槽
        self.info_treeWidget.doubleClicked.connect(self.handleDoubleClick)
        self.info_treeWidget.clicked.connect(self.seeingSingleClick)
        self.click_time = QTimer(self)
        self.click_time.timeout.connect(self.handleSingleClick)
        self.correctrow = -1  # 初始化选择的正确的行
        self.correctid = 0  # 初始化包的id

    def filter_test(self):
        """
        过滤器显示静态
        :return: None
        """
        filter_text = self.filter_edit.text()
        filter_rule = sl_jd(filter_text)
        if not filter_rule:
            self.filter_edit.setStyleSheet("background-color:#FFAFAF")
        else:
            if filter_text == "":
                self.filter_edit.setStyleSheet("background-color:#FFFFFF")
                self.list_select = self.sni.packetlist.copy()
            else:
                self.filter_edit.setStyleSheet("background-color:#AFFFAF")
                self.list_select = select_pk(self.sni.packetlist, filter_rule).copy()
            self.load_infaceinfo()

    def filter_update(self):
        """
        过滤器动态显示
        :return: Nonoe
        """
        newfilter_text = self.filter_edit2.text()
        if newfilter_text == self.filter_text:
            return
        self.filter_text = newfilter_text
        new_filter_rule = sl_jd(self.filter_text)
        if not new_filter_rule:
            self.filter_edit2.setStyleSheet("background-color:#FFAFAF")
            return
        else:
            self.filter_rule = new_filter_rule
            self.filter_edit2.setStyleSheet("background-color:#AFFFAF")
            self.info_treeWidget.clear()
            # 正在执行
            if not self.start.isEnabled() and self.pause.isEnabled() \
                    and self.stop.isEnabled() and not self.restart.isEnabled():
                self.sni.pause()
                time.sleep(0.5)
                self.info_treeWidget.clear()
                if self.filter_text == "":
                    self.filter_edit2.setStyleSheet("background-color:#FFFFFF")
                    self.list_select = self.sni.packetlist.copy()
                    sni_start = threading.Thread(target=self.update_infaceinfo, daemon=True)
                    sni_start.start()
                else:
                    sni_start1 = threading.Thread(target=self.update_infaceinfo2, daemon=True)
                    sni_start1.start()
            # 正在暂停
            elif not self.start.isEnabled() and not self.pause.isEnabled() \
                    and self.stop.isEnabled() and self.restart.isEnabled():
                time.sleep(1)
                self.info_treeWidget.clear()
                if self.filter_text == "":
                    self.filter_edit2.setStyleSheet("background-color:#FFFFFF")
                    try:
                        self.list_select = self.sni.packetlist.copy()
                    except Exception as e:
                        raise Exception
                else:
                    try:
                        self.list_select = select_pk(self.sni.packetlist, self.filter_rule).copy()
                    except Exception as e:
                        raise Exception
                self.load_infaceinfo()
            # 捕获已经停止
            elif not self.start.isEnabled() and not self.pause.isEnabled() and not self.stop.isEnabled() and self.restart.isEnabled():
                time.sleep(0.5)
                self.info_treeWidget.clear()
                if self.filter_text == "":
                    self.filter_edit2.setStyleSheet("background-color:#FFFFFF")
                    try:
                        self.list_select = self.sni.packetlist.copy()
                    except Exception as e:
                        raise Exception
                else:
                    try:
                        self.list_select = select_pk(self.sni.packetlist, self.filter_rule).copy()
                    except Exception as e:
                        raise Exception
                self.load_infaceinfo()

    def filter_init(self):
        """
        初始化过滤器显示
        :return: None
        """
        self.is_save = False
        self.filter_text = self.filter_edit2.text()
        self.filter_rule = sl_jd(self.filter_text)
        if not self.filter_rule:
            self.filter_edit2.setStyleSheet("background-color:#FFAFAF")
        else:
            self.filter_edit2.setStyleSheet("background-color:#AFFFAF")
            self.info_treeWidget.clear()
            if not self.sni.stopflag:
                if not self.sni.pauseflag:
                    self.sni.pause()
                    time.sleep(0.5)
                    self.info_treeWidget.clear()
                    if self.filter_text == "":
                        self.filter_edit2.setStyleSheet("background-color:#FFFFFF")
                        self.list_select = self.sni.packetlist.copy()
                        sni_start = threading.Thread(target=self.update_infaceinfo, daemon=True)
                        sni_start.start()
                    else:
                        sni_start1 = threading.Thread(target=self.update_infaceinfo2, daemon=True)
                        sni_start1.start()
                else:
                    time.sleep(0.5)
                    self.info_treeWidget.clear()
                    if self.filter_text == "":
                        self.filter_edit2.setStyleSheet("background-color:#FFFFFF")
                        self.list_select = self.sni.packetlist.copy()
                    else:
                        self.list_select = select_pk(self.sni.packetlist, self.filter_rule).copy()
                    self.load_infaceinfo()

            else:
                time.sleep(0.5)
                self.info_treeWidget.clear()
                if self.filter_text == "":
                    self.filter_edit2.setStyleSheet("background-color:#FFFFFF")
                    self.list_select = self.sni.packetlist.copy()
                else:
                    self.list_select = select_pk(self.sni.packetlist, self.filter_rule).copy()
                self.load_infaceinfo()

    def update_infaceinfo2(self):
        """
        更新数据包,过滤器使用
        :return: None
        """
        self.info_treeWidget.clear()
        self.sni.start()
        self.correctrow = -1
        self.correctid = 0
        self.treepack = 0
        lengthold = 0
        while True:
            try:
                if self.sni.stopflag == True or self.sni.pauseflag == True:
                    self.list_select.clear()
                    return
                self.sni.pause()
                time.sleep(0.5)
                lengthnew = len(self.sni.packetlist)
                self.list_select = select_pk(self.sni.packetlist[lengthold:lengthnew], self.filter_rule).copy()
                self.sni.start()
                if lengthold != lengthnew:
                    correct_length = len(self.list_select)
                    self.treepack += correct_length
                    for j in range(correct_length):
                        if self.sni.stopflag == True or self.sni.pauseflag == True:
                            self.list_select.clear()
                            return
                        else:
                            if self.list_select:
                                try:
                                    item = QTreeWidgetItem(self.info_treeWidget)
                                    item.setText(0, str(self.list_select[j]["No"]))
                                    item.setText(1, str(self.list_select[j]["Time"]))
                                    item.setText(2, str(self.list_select[j]["Src"]))
                                    item.setText(3, str(self.list_select[j]["Dst"]))
                                    item.setText(4, str(self.list_select[j]["Proto"]))
                                    item.setText(5, str(self.list_select[j]["Len"]))
                                    item.setText(6, str(self.list_select[j]["Info"]))
                                    if self.list_select[j]["Proto"] == "TCP" or self.list_select[j]["Proto"] == "TCPv6" \
                                            or self.list_select[j]["Proto"] == "DNS" or self.list_select[j][
                                        "Proto"] == "DNSv6":
                                        item.setBackground(0, QBrush(QColor(231, 230, 255)))
                                        item.setBackground(1, QBrush(QColor(231, 230, 255)))
                                        item.setBackground(2, QBrush(QColor(231, 230, 255)))
                                        item.setBackground(3, QBrush(QColor(231, 230, 255)))
                                        item.setBackground(4, QBrush(QColor(231, 230, 255)))
                                        item.setBackground(5, QBrush(QColor(231, 230, 255)))
                                        item.setBackground(6, QBrush(QColor(231, 230, 255)))

                                    elif self.list_select[j]["Proto"] == "UDP" or self.list_select[j]["Proto"] == "MDNS" \
                                            or self.list_select[j]["Proto"] == "SSDP" or \
                                            self.list_select[j]["Proto"] == "MDNSv6" \
                                            or self.list_select[j]["Proto"] == "SSDPv6" \
                                            or self.list_select[j]["Proto"] == "UDPv6":
                                        item.setBackground(0, QBrush(QColor(218, 238, 255)))
                                        item.setBackground(1, QBrush(QColor(218, 238, 255)))
                                        item.setBackground(2, QBrush(QColor(218, 238, 255)))
                                        item.setBackground(3, QBrush(QColor(218, 238, 255)))
                                        item.setBackground(4, QBrush(QColor(218, 238, 255)))
                                        item.setBackground(5, QBrush(QColor(218, 238, 255)))
                                        item.setBackground(6, QBrush(QColor(218, 238, 255)))

                                    elif self.list_select[j]["Proto"] == "HTTPS":
                                        item.setBackground(0, QBrush(QColor(210, 255, 199)))
                                        item.setBackground(1, QBrush(QColor(210, 255, 199)))
                                        item.setBackground(2, QBrush(QColor(210, 255, 199)))
                                        item.setBackground(3, QBrush(QColor(210, 255, 199)))
                                        item.setBackground(4, QBrush(QColor(210, 255, 199)))
                                        item.setBackground(5, QBrush(QColor(210, 255, 199)))
                                        item.setBackground(6, QBrush(QColor(210, 255, 199)))


                                    elif self.list_select[j]["Proto"] == "HTTP":
                                        item.setBackground(0, QBrush(QColor(228, 255, 199)))
                                        item.setBackground(1, QBrush(QColor(228, 255, 199)))
                                        item.setBackground(2, QBrush(QColor(228, 255, 199)))
                                        item.setBackground(3, QBrush(QColor(228, 255, 199)))
                                        item.setBackground(4, QBrush(QColor(228, 255, 199)))
                                        item.setBackground(5, QBrush(QColor(228, 255, 199)))
                                        item.setBackground(6, QBrush(QColor(228, 255, 199)))

                                    elif self.list_select[j]["Proto"] == "ICMP" or self.list_select[j][
                                        "Proto"] == "ICMPv6":
                                        item.setBackground(0, QBrush(QColor(252, 224, 255)))
                                        item.setBackground(1, QBrush(QColor(252, 224, 255)))
                                        item.setBackground(2, QBrush(QColor(252, 224, 255)))
                                        item.setBackground(3, QBrush(QColor(252, 224, 255)))
                                        item.setBackground(4, QBrush(QColor(252, 224, 255)))
                                        item.setBackground(5, QBrush(QColor(252, 224, 255)))
                                        item.setBackground(6, QBrush(QColor(252, 224, 255)))

                                    elif self.list_select[j]["Proto"] == "ARP":
                                        item.setBackground(0, QBrush(QColor(255, 240, 210)))
                                        item.setBackground(1, QBrush(QColor(255, 240, 210)))
                                        item.setBackground(2, QBrush(QColor(255, 240, 210)))
                                        item.setBackground(3, QBrush(QColor(255, 240, 210)))
                                        item.setBackground(4, QBrush(QColor(255, 240, 210)))
                                        item.setBackground(5, QBrush(QColor(255, 240, 210)))
                                        item.setBackground(6, QBrush(QColor(255, 240, 210)))
                                except:
                                    pass
                            else:
                                pass
                    lengthold = lengthnew
                    time.sleep(1)
                else:
                    time.sleep(1)
                self.refresh(lengthnew)
            except Exception as e:
                raise Exception

    def handleDoubleClick(self):
        """
        双击事件，展开弹窗
        :return: None
        """
        try:
            self.click_time.stop()
            self.doubleclick_flag = True
            self.select_packet = self.sni.get_packet_by_id(self.correctid)
            if self.select_packet == "Error":
                reply = QMessageBox.critical(self, "错误", "没有分析出该包，请稍等！", QMessageBox.Close)
                if reply == QMessageBox.Close:
                    return
            else:
                self.hexstr = self.sni.get_hexdump(self.select_packet)
                a = []
                self.layer = self.sni.get_detailed_packet(self.select_packet, a, self.correctid)
                if self.layer == "Error":
                    reply = QMessageBox.critical(self, "错误", "没有分析出该包，请稍等！", QMessageBox.Close)
                    if reply == QMessageBox.Close:
                        return
                else:
                    self.info_pack.clear()
                    self.read_layer(self.layer)
                    self.packet = Packet_information(self.layer, self.hexstr)
                    self.packet.show()
        except:
            pass

    def seeingSingleClick(self, item):
        """
        单击表格显示分组16进制字符和分组展开
        :param item: 表格中的对象
        :return: None
        """
        try:
            row = item.row()
            item1 = self.info_treeWidget.currentItem()
            if row < 1000:
                qApp.setDoubleClickInterval(200)
            else:
                qApp.setDoubleClickInterval(500)
            self.click_time.start(qApp.doubleClickInterval())
            if self.correctrow == row:
                return
            else:
                self.info_pack.clear()
                self.doubleclick_flag = False
                self.correctrow = row
            # self.correctid = self.list_select[self.correctrow]["No"]
            self.correctid = int(item1.text(0))
        except:
            pass

    def handleSingleClick(self):
        """
        单击表格显示分组16进制字符和分组展开
        :return: None
        """
        self.click_time.stop()
        try:
            if self.doubleclick_flag == False:
                self.select_packet = self.sni.get_packet_by_id(self.correctid)
                if self.select_packet == "Error":
                    reply = QMessageBox.critical(self, "错误", "没有找到该分组，请稍等！", QMessageBox.Close)
                    if reply == QMessageBox.Close:
                        return
                else:
                    a = []
                    self.layer = self.sni.get_detailed_packet(self.select_packet, a, self.correctid)
                    if self.layer == "Error":
                        reply = QMessageBox.critical(self, "错误", "没有分析出该分组，请稍等！", QMessageBox.Close)
                        if reply == QMessageBox.Close:
                            return
                    else:
                        self.info_pack.clear()
                        self.pac_hexnew.clear()
                        self.read_layer(self.layer)
                        hexstr = self.sni.get_hexdump(self.select_packet)
                        self.pac_hexnew.setPlainText(hexstr)
            else:
                self.info_pack.setFont(self.font)
                return
        except:
            pass

    def read_layer(self, layer):
        """
        逐层展开包，并显示.(递归实现）
        :param layer:
        :return:None
        """
        length = len(layer)
        if length == 0:
            return
        item1 = QTreeWidgetItem(self.info_pack)
        for i in range(length):
            if i == length - 1:
                if isinstance(layer[i], list):
                    self.read_layer(layer[i])
                else:
                    QTreeWidgetItem(item1).setText(0, str(layer[i]))
            elif isinstance(layer[i], list):
                self.read_layer(layer[i])
            elif i == 0:
                item1.setText(0, str(layer[i]))
            else:
                QTreeWidgetItem(item1).setText(0, str(layer[i]))

    def startsniff(self):
        """
        加载开始实时监听数据包的界面
        :return: None
        """
        self.ui_id = 2
        self.start.setEnabled(False)
        self.pause.setEnabled(True)
        self.restart.setEnabled(False)
        self.stop.setEnabled(True)

        self.open.setEnabled(False)
        self.close.setEnabled(True)
        self.save.setEnabled(True)

        self.view1.setEnabled(True)
        self.view2.setEnabled(True)
        self.view3.setEnabled(True)
        self.tree_no.setEnabled(True)
        self.tree_time.setEnabled(True)
        self.tree_source.setEnabled(True)
        self.tree_destination.setEnabled(True)
        self.tree_protocol.setEnabled(True)
        self.tree_length.setEnabled(True)
        self.tree_info.setEnabled(True)

        self.is_save = False
        self.statics.setEnabled(True)
        self.sni = Capture(self.default_inface)

        centralwidget1 = QWidget(self)
        layout = QVBoxLayout()

        # 定义一个过滤器输入框
        self.filter_edit2 = QLineEdit()
        self.filter_edit2.setMaximumWidth(1890)
        self.filter_edit2.setMinimumWidth(690)
        self.filter_edit2.setFixedHeight(20)
        self.filter_edit2.editingFinished.connect(self.filter_update)
        self.filter_edit2.setPlaceholderText("输入过滤规则")
        self.info_pack = QTreeWidget()
        self.info_pack.clear()
        # self.info_pack.setFixedHeight(440)
        # self.info_pack.setFixedWidth(1890)
        # 设置字体
        self.info_pack.setFont(self.font)
        # 设置列数
        self.info_pack.setColumnCount(1)
        # 隐藏表头
        self.info_pack.header().hide()

        self.info_pack.setFrameStyle(QFrame.Box | QFrame.Plain)

        # 显示基础包的信息的表格
        self.info_treeWidget = QTreeWidget()
        self.info_treeWidget.setColumnCount(7)
        self.info_treeWidget.setHeaderLabels(['No', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        # self.info_treeWidget.header().hide() #表头隐藏
        self.info_treeWidget.setSelectionMode(QTreeWidget.SingleSelection)  # 设置只能选中一行
        self.info_treeWidget.setSelectionBehavior(QTreeWidget.SelectRows)  # 整行选择
        self.info_treeWidget.setAutoScroll(True)  # 自动滚动
        self.info_treeWidget.setFrameStyle(QFrame.Box | QFrame.Plain)
        # self.info_treeWidget.setFixedWidth(1890)
        # self.info_treeWidget.setFixedHeight(440)
        self.info_treeWidget.setUniformRowHeights(True)

        self.info_treeWidget.setFont(self.font)

        self.info_treeWidget.setColumnWidth(0, 100)
        self.info_treeWidget.setColumnWidth(1, 150)
        self.info_treeWidget.setColumnWidth(2, 200)
        self.info_treeWidget.setColumnWidth(3, 200)
        self.info_treeWidget.setColumnWidth(4, 130)
        self.info_treeWidget.setColumnWidth(5, 130)
        self.info_treeWidget.setColumnWidth(5, 130)
        self.info_treeWidget.setColumnWidth(6, 950)
        self.info_treeWidget.setStyleSheet("selection-background-color:blue")
        # row = self.info_treeWidget.rowCount()

        # 连接点击事件到槽
        self.info_treeWidget.doubleClicked.connect(self.handleDoubleClick)
        self.info_treeWidget.clicked.connect(self.seeingSingleClick)
        self.click_time = QTimer(self)
        self.click_time.timeout.connect(self.handleSingleClick)
        self.correctrow = -1  # 初始化选择的正确的行
        self.correctid = 0  # 初始化包的id

        # 显示包的十六进制的QTextEdit
        self.pac_hexnew = QTextEdit()
        self.pac_hexnew.setReadOnly(True)  # 不可编辑
        self.pac_hexnew.setFrameStyle(QFrame.Box | QFrame.Plain)
        self.pac_hexnew.setFont(self.font)

        layout.addWidget(self.filter_edit2)
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.info_treeWidget)
        splitter.addWidget(self.info_pack)
        splitter.addWidget(self.pac_hexnew)
        layout.addWidget(splitter)
        # layout.addWidget(self.info_treeWidget)
        # layout.addWidget(self.info_pack)

        centralwidget1.setLayout(layout)
        self.setCentralWidget(centralwidget1)
        # self.sni_start = threading.Thread(target=self.start_sniff, daemon=True)
        # self.sni_start.start()
        self.start_sniff()

    def start_sniff(self):
        """
        开启监听程序,启动监听流量的类，过滤器初始化
        :return: None
        """
        self.is_save == False
        self.sni.start()
        self.filter_init()
        # self.update_infaceinfo()

    def load_infaceinfo(self):
        """
        加载数据包用的更新,用来加载已经保存好的pcap
        :return: None
        """
        self.info_treeWidget.clear()
        sni_pac_length = len(self.sni.packetlist)
        length = len(self.list_select)
        for j in range(length):
            item = QTreeWidgetItem(self.info_treeWidget)
            item.setText(0, str(self.list_select[j]["No"]))
            item.setText(1, str(self.list_select[j]["Time"]))
            item.setText(2, str(self.list_select[j]["Src"]))
            item.setText(3, str(self.list_select[j]["Dst"]))
            item.setText(4, str(self.list_select[j]["Proto"]))
            item.setText(5, str(self.list_select[j]["Len"]))
            item.setText(6, str(self.list_select[j]["Info"]))
            if self.list_select[j]["Proto"] == "TCP" or self.list_select[j]["Proto"] == "TCPv6" \
                    or self.list_select[j]["Proto"] == "DNS" or self.list_select[j]["Proto"] == "DNSv6":
                item.setBackground(0, QBrush(QColor(231, 230, 255)))
                item.setBackground(1, QBrush(QColor(231, 230, 255)))
                item.setBackground(2, QBrush(QColor(231, 230, 255)))
                item.setBackground(3, QBrush(QColor(231, 230, 255)))
                item.setBackground(4, QBrush(QColor(231, 230, 255)))
                item.setBackground(5, QBrush(QColor(231, 230, 255)))
                item.setBackground(6, QBrush(QColor(231, 230, 255)))

            elif self.list_select[j]["Proto"] == "UDP" or self.list_select[j]["Proto"] == "MDNS" \
                    or self.list_select[j]["Proto"] == "SSDP" or \
                    self.list_select[j]["Proto"] == "MDNSv6" \
                    or self.list_select[j]["Proto"] == "SSDPv6" \
                    or self.list_select[j]["Proto"] == "UDPv6":
                item.setBackground(0, QBrush(QColor(218, 238, 255)))
                item.setBackground(1, QBrush(QColor(218, 238, 255)))
                item.setBackground(2, QBrush(QColor(218, 238, 255)))
                item.setBackground(3, QBrush(QColor(218, 238, 255)))
                item.setBackground(4, QBrush(QColor(218, 238, 255)))
                item.setBackground(5, QBrush(QColor(218, 238, 255)))
                item.setBackground(6, QBrush(QColor(218, 238, 255)))

            elif self.list_select[j]["Proto"] == "HTTPS":
                item.setBackground(0, QBrush(QColor(210, 255, 199)))
                item.setBackground(1, QBrush(QColor(210, 255, 199)))
                item.setBackground(2, QBrush(QColor(210, 255, 199)))
                item.setBackground(3, QBrush(QColor(210, 255, 199)))
                item.setBackground(4, QBrush(QColor(210, 255, 199)))
                item.setBackground(5, QBrush(QColor(210, 255, 199)))
                item.setBackground(6, QBrush(QColor(210, 255, 199)))


            elif self.list_select[j]["Proto"] == "HTTP":
                item.setBackground(0, QBrush(QColor(228, 255, 199)))
                item.setBackground(1, QBrush(QColor(228, 255, 199)))
                item.setBackground(2, QBrush(QColor(228, 255, 199)))
                item.setBackground(3, QBrush(QColor(228, 255, 199)))
                item.setBackground(4, QBrush(QColor(228, 255, 199)))
                item.setBackground(5, QBrush(QColor(228, 255, 199)))
                item.setBackground(6, QBrush(QColor(228, 255, 199)))

            elif self.list_select[j]["Proto"] == "ICMP" or self.list_select[j]["Proto"] == "ICMPv6":
                item.setBackground(0, QBrush(QColor(252, 224, 255)))
                item.setBackground(1, QBrush(QColor(252, 224, 255)))
                item.setBackground(2, QBrush(QColor(252, 224, 255)))
                item.setBackground(3, QBrush(QColor(252, 224, 255)))
                item.setBackground(4, QBrush(QColor(252, 224, 255)))
                item.setBackground(5, QBrush(QColor(252, 224, 255)))
                item.setBackground(6, QBrush(QColor(252, 224, 255)))

            elif self.list_select[j]["Proto"] == "ARP":
                item.setBackground(0, QBrush(QColor(255, 240, 210)))
                item.setBackground(1, QBrush(QColor(255, 240, 210)))
                item.setBackground(2, QBrush(QColor(255, 240, 210)))
                item.setBackground(3, QBrush(QColor(255, 240, 210)))
                item.setBackground(4, QBrush(QColor(255, 240, 210)))
                item.setBackground(5, QBrush(QColor(255, 240, 210)))
                item.setBackground(6, QBrush(QColor(255, 240, 210)))
        self.number_tree()
        self.refresh(sni_pac_length)

    def update_infaceinfo(self):
        """
        更新数据包,没有进行过滤
        :return: None
        """
        self.info_treeWidget.clear()
        self.sni.start()
        self.correctrow = -1
        self.correctid = 0
        lengthold = 0
        self.treepack = 0
        while True:
            try:
                if self.sni.stopflag == True or self.sni.pauseflag == True:
                    self.list_select.clear()
                    return
                self.sni.pause()
                lengthnew = len(self.sni.packetlist)
                self.list_select = self.sni.packetlist[lengthold:].copy()
                self.sni.start()
                if lengthold != lengthnew:
                    self.treepack += lengthnew - lengthold
                    for j in range(lengthnew - lengthold):
                        if self.sni.stopflag == True or self.sni.pauseflag == True:
                            self.list_select.clear()
                            return
                        else:
                            if self.list_select:
                                item = QTreeWidgetItem(self.info_treeWidget)
                                item.setText(0, str(self.list_select[j]["No"]))
                                item.setText(1, str(self.list_select[j]["Time"]))
                                item.setText(2, str(self.list_select[j]["Src"]))
                                item.setText(3, str(self.list_select[j]["Dst"]))
                                item.setText(4, str(self.list_select[j]["Proto"]))
                                item.setText(5, str(self.list_select[j]["Len"]))
                                item.setText(6, str(self.list_select[j]["Info"]))
                                if self.list_select[j]["Proto"] == "TCP" or self.list_select[j]["Proto"] == "TCPv6" \
                                        or self.list_select[j]["Proto"] == "DNS" or self.list_select[j][
                                    "Proto"] == "DNSv6":
                                    item.setBackground(0, QBrush(QColor(231, 230, 255)))
                                    item.setBackground(1, QBrush(QColor(231, 230, 255)))
                                    item.setBackground(2, QBrush(QColor(231, 230, 255)))
                                    item.setBackground(3, QBrush(QColor(231, 230, 255)))
                                    item.setBackground(4, QBrush(QColor(231, 230, 255)))
                                    item.setBackground(5, QBrush(QColor(231, 230, 255)))
                                    item.setBackground(6, QBrush(QColor(231, 230, 255)))

                                elif self.list_select[j]["Proto"] == "UDP" or self.list_select[j]["Proto"] == "MDNS" \
                                        or self.list_select[j]["Proto"] == "SSDP" or \
                                        self.list_select[j]["Proto"] == "MDNSv6" \
                                        or self.list_select[j]["Proto"] == "SSDPv6" \
                                        or self.list_select[j]["Proto"] == "UDPv6":
                                    item.setBackground(0, QBrush(QColor(218, 238, 255)))
                                    item.setBackground(1, QBrush(QColor(218, 238, 255)))
                                    item.setBackground(2, QBrush(QColor(218, 238, 255)))
                                    item.setBackground(3, QBrush(QColor(218, 238, 255)))
                                    item.setBackground(4, QBrush(QColor(218, 238, 255)))
                                    item.setBackground(5, QBrush(QColor(218, 238, 255)))
                                    item.setBackground(6, QBrush(QColor(218, 238, 255)))

                                elif self.list_select[j]["Proto"] == "HTTPS":
                                    item.setBackground(0, QBrush(QColor(210, 255, 199)))
                                    item.setBackground(1, QBrush(QColor(210, 255, 199)))
                                    item.setBackground(2, QBrush(QColor(210, 255, 199)))
                                    item.setBackground(3, QBrush(QColor(210, 255, 199)))
                                    item.setBackground(4, QBrush(QColor(210, 255, 199)))
                                    item.setBackground(5, QBrush(QColor(210, 255, 199)))
                                    item.setBackground(6, QBrush(QColor(210, 255, 199)))


                                elif self.list_select[j]["Proto"] == "HTTP":
                                    item.setBackground(0, QBrush(QColor(228, 255, 199)))
                                    item.setBackground(1, QBrush(QColor(228, 255, 199)))
                                    item.setBackground(2, QBrush(QColor(228, 255, 199)))
                                    item.setBackground(3, QBrush(QColor(228, 255, 199)))
                                    item.setBackground(4, QBrush(QColor(228, 255, 199)))
                                    item.setBackground(5, QBrush(QColor(228, 255, 199)))
                                    item.setBackground(6, QBrush(QColor(228, 255, 199)))

                                elif self.list_select[j]["Proto"] == "ICMP" or self.list_select[j]["Proto"] == "ICMPv6":
                                    item.setBackground(0, QBrush(QColor(252, 224, 255)))
                                    item.setBackground(1, QBrush(QColor(252, 224, 255)))
                                    item.setBackground(2, QBrush(QColor(252, 224, 255)))
                                    item.setBackground(3, QBrush(QColor(252, 224, 255)))
                                    item.setBackground(4, QBrush(QColor(252, 224, 255)))
                                    item.setBackground(5, QBrush(QColor(252, 224, 255)))
                                    item.setBackground(6, QBrush(QColor(252, 224, 255)))

                                elif self.list_select[j]["Proto"] == "ARP":
                                    item.setBackground(0, QBrush(QColor(255, 240, 210)))
                                    item.setBackground(1, QBrush(QColor(255, 240, 210)))
                                    item.setBackground(2, QBrush(QColor(255, 240, 210)))
                                    item.setBackground(3, QBrush(QColor(255, 240, 210)))
                                    item.setBackground(4, QBrush(QColor(255, 240, 210)))
                                    item.setBackground(5, QBrush(QColor(255, 240, 210)))
                                    item.setBackground(6, QBrush(QColor(255, 240, 210)))
                            else:
                                pass
                    # self.info_treeWidget.scrollToBottom()
                    lengthold = lengthnew
                    time.sleep(1)
                else:
                    time.sleep(1)
                self.refresh(lengthnew)
            except Exception as e:
                raise Exception

    def pausesniff(self):
        """
        暂停窃听数据报文
        :return: None
        """
        self.start.setEnabled(False)
        self.pause.setEnabled(False)
        self.restart.setEnabled(True)
        self.stop.setEnabled(True)
        self.restart.setToolTip("继续当前捕获")
        self.sni.pause()

    def stopsniff(self):
        """
        停止窃听数据报文
        :return: None
        """
        self.start.setEnabled(False)
        self.pause.setEnabled(False)
        self.restart.setEnabled(True)
        self.stop.setEnabled(False)
        self.restart.setToolTip("重新开始当前捕获")
        self.sni.stop()
        # self.info_treeWidget.clear()

    def restartsniff(self):
        """
        重新开始抓取数据报文
        :return: None
        """
        if self.is_save == False:
            if not self.start.isEnabled() and not self.pause.isEnabled() and not self.stop.isEnabled() and self.restart.isEnabled():
                message_widget = QMessageBox.question(
                    self, '警告', "捕获已经停止，重新开始会导致刚刚捕获的数据包丢失！\n是否进行保存",
                    QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel, QMessageBox.Cancel)
                if message_widget == QMessageBox.Cancel:
                    pass
                elif message_widget == QMessageBox.No:
                    self.info_treeWidget.clear()
                    self.start.setEnabled(False)
                    self.pause.setEnabled(True)
                    self.restart.setEnabled(False)
                    self.stop.setEnabled(True)
                    sni_start = threading.Thread(target=self.start_sniff, daemon=True)
                    sni_start.start()
                elif message_widget == QMessageBox.Yes:
                    self.sni.stop()
                    time.sleep(1)
                    if self.savepcap:
                        self.info_treeWidget.clear()
                        self.start.setEnabled(False)
                        self.pause.setEnabled(True)
                        self.restart.setEnabled(False)
                        self.stop.setEnabled(True)
                        sni_start = threading.Thread(target=self.start_sniff, daemon=True)
                        sni_start.start()
                    else:
                        return
            elif not self.start.isEnabled() and not self.pause.isEnabled() and self.stop.isEnabled() and self.restart.isEnabled():
                self.info_treeWidget.clear()
                self.start.setEnabled(False)
                self.pause.setEnabled(True)
                self.restart.setEnabled(False)
                self.stop.setEnabled(True)
                sni_start = threading.Thread(target=self.start_sniff, daemon=True)
                sni_start.start()
        elif self.is_save == True:
            if not self.start.isEnabled() and not self.pause.isEnabled() and not self.stop.isEnabled() and self.restart.isEnabled():
                self.info_treeWidget.clear()
                self.start.setEnabled(False)
                self.pause.setEnabled(True)
                self.restart.setEnabled(False)
                self.stop.setEnabled(True)
                sni_start = threading.Thread(target=self.start_sniff, daemon=True)
                sni_start.start()
            elif not self.start.isEnabled() and not self.pause.isEnabled() and self.stop.isEnabled() and self.restart.isEnabled():
                self.info_treeWidget.clear()
                self.start.setEnabled(False)
                self.pause.setEnabled(True)
                self.restart.setEnabled(False)
                self.stop.setEnabled(True)
                sni_start = threading.Thread(target=self.start_sniff, daemon=True)
                sni_start.start()

    def openMsg(self):
        """
        打开系统中存在的pcap数据包
        :return: None
        """
        try:
            # file_name, ok = QFileDialog.getOpenFileName(self, "打开", "D:/pythonproject/qttest", "All Files (*);;Text Files (*.pcap)")
            file_name, ok = QFileDialog.getOpenFileName(self, "打开", os.getcwd(),
                                                        "Pcap Files (*.pcap)")
            if file_name == "":
                return
            self.statusBar.showMessage(file_name)
            self.sni = Capture("WLAN")
            if self.sni.load_pcap(file_name):
                self.open_latest_pacp(file_name)
                self.load_pcap()
            else:
                reply = QMessageBox.critical(self, "错误", "打不开该分组文件！", QMessageBox.Close)
                if reply == QMessageBox.Close:
                    return
        except Exception as e:
            raise Exception
            pass

    def savepcap(self):
        """
        保存正在进行的数据包
        :return: 成功则为success，否则false
        """
        self.stopsniff()
        try:
            file_name, ok = QFileDialog.getSaveFileName(self, "保存", os.getcwd(),
                                                        "Pcap Files (*.pcap)")
            if file_name == "":
                return False
            traverse_pac = self.traverse_tree()
            is_filter = self.filter_edit2.text()
            if is_filter == "":
                if self.sni.save_pcap(file_name):
                    reply = QMessageBox.information(self, "恭喜你", "保存成功", QMessageBox.Ok)
                    if reply == QMessageBox.Ok:
                        self.is_save = True
                        return True
                    return True
                else:
                    reply = QMessageBox.critical(self, "错误", "保存失败了", QMessageBox.Close)
                    if reply == QMessageBox.Close:
                        return False
                    return False
            else:
                if self.sni.save_pcap(file_name, traverse_pac):
                    reply = QMessageBox.information(self, "恭喜你", "保存成功", QMessageBox.Ok)
                    if reply == QMessageBox.Ok:
                        self.is_save = True
                        return True
                    return True
                else:
                    reply = QMessageBox.critical(self, "错误", "保存失败了", QMessageBox.Close)
                    if reply == QMessageBox.Close:
                        return False
                    return False
        except:
            return False
            pass

    def close_sni_widget(self):
        """
        关闭窃听窗口，返回主页
        :return: None
        """
        self.info_pack.clear()
        self.info_pack.close()
        self.info_treeWidget.clear()
        self.info_treeWidget.close()
        self.pac_hexnew.clear()
        self.pac_hexnew.close()
        self.startwireshark()

    def closeEvent(self, QCloseEvent):
        """
        对关闭事件重写
        :param QCloseEvent: 关闭的信号
        :return: None
        """
        if self.ui_id == 2:
            if self.is_save == False:
                # 捕获过程中关闭
                if not self.start.isEnabled() and self.pause.isEnabled() \
                        and self.stop.isEnabled() and not self.restart.isEnabled():
                    message_widget = QMessageBox.question(
                        self, '警告', "捕获正在进行中，是否停止捕获，保存分组？\n不保存分组将会丢失",
                        QMessageBox.Save | QMessageBox.Close | QMessageBox.Cancel, QMessageBox.Cancel)
                    if message_widget == QMessageBox.Cancel:
                        pass
                    elif message_widget == QMessageBox.Close:
                        self.sni.stop()
                        self.close_sni_widget()
                    elif message_widget == QMessageBox.Save:
                        self.sni.stop()
                        if self.savepcap:
                            self.close_sni_widget()
                        else:
                            return
                elif not self.start.isEnabled() and not self.pause.isEnabled() and not self.stop.isEnabled() and not self.restart.isEnabled():
                    self.close_sni_widget()
                elif not self.start.isEnabled() and not self.pause.isEnabled() and self.stop.isEnabled() and self.restart.isEnabled():
                    message_widget = QMessageBox.question(
                        self, '警告', "捕获暂停中，是否停止捕获并保存分组？\n不保存分组将会丢失",
                        QMessageBox.Save | QMessageBox.Close | QMessageBox.Cancel, QMessageBox.Cancel)
                    if message_widget == QMessageBox.Cancel:
                        pass
                    elif message_widget == QMessageBox.Close:
                        self.sni.stop()
                        self.close_sni_widget()
                    elif message_widget == QMessageBox.Save:
                        self.sni.stop()
                        if self.savepcap:
                            self.close_sni_widget()
                        else:
                            return
                elif not self.start.isEnabled() and not self.pause.isEnabled() and not self.stop.isEnabled() and self.restart.isEnabled():
                    message_widget = QMessageBox.question(
                        self, '警告', "捕获已经结束，是否停止捕获并保存分组？\n不保存分组将会丢失",
                        QMessageBox.Save | QMessageBox.Close | QMessageBox.Cancel, QMessageBox.Cancel)
                    if message_widget == QMessageBox.Cancel:
                        pass
                    elif message_widget == QMessageBox.Close:
                        self.close_sni_widget()
                    elif message_widget == QMessageBox.Save:
                        self.sni.stop()
                        if self.savepcap:
                            self.close_sni_widget()
                        else:
                            return
            else:
                self.close_sni_widget()
        elif self.ui_id == 3:
            self.startwireshark()

    def traverse_tree(self):
        """
        遍历获取过滤的包的ID
        :return:traverse_pac:包含所有过滤出来的包的id
        """
        traverse_pac = []
        iterator = QTreeWidgetItemIterator(self.info_treeWidget)
        while iterator.value():
            item = iterator.value()
            traverse_pac.append(int(item.text(0)))
            iterator.__iadd__(1)
        return traverse_pac

    def number_tree(self):
        """
        获取树形表格的子数目
        :return: None
        """
        self.treepack = 0
        iterator = QTreeWidgetItemIterator(self.info_treeWidget)
        while iterator.value():
            item = iterator.value()
            self.treepack += 1
            iterator.__iadd__(1)

    def UI_layout(self):
        """
        进行窗口布局选择
        :return: None
        """
        layout = QVBoxLayout()
        self.layout2 = QVBoxLayout()
        splitter = QSplitter(Qt.Vertical)
        splitter1 = QSplitter(Qt.Vertical)
        if self.ui_id == 2:
            centralwidget1 = QWidget(self)
            layout.addWidget(self.filter_edit2)
            self.layout2.addWidget(self.filter_edit2)
            if self.view1.isChecked():
                splitter.addWidget(self.info_treeWidget)
            else:
                splitter1.addWidget(self.info_treeWidget)
            if self.view2.isChecked():
                splitter.addWidget(self.info_pack)
            else:
                splitter1.addWidget(self.info_pack)
            if self.view3.isChecked():
                splitter.addWidget(self.pac_hexnew)
            else:
                splitter1.addWidget(self.pac_hexnew)
            self.layout2.addWidget(splitter1)
            layout.addWidget(splitter)
            centralwidget1.setLayout(layout)
            self.setCentralWidget(centralwidget1)
        if self.ui_id == 3:
            centralwidget1 = QWidget(self)
            layout.addWidget(self.filter_edit)
            self.layout2.addWidget(self.filter_edit)
            if self.view1.isChecked():
                splitter.addWidget(self.info_treeWidget)
            else:
                splitter1.addWidget(self.info_treeWidget)
            if self.view2.isChecked():
                splitter.addWidget(self.info_pack)
            else:
                splitter1.addWidget(self.info_pack)
            if self.view3.isChecked():
                splitter.addWidget(self.pac_hexnew)
            else:
                splitter1.addWidget(self.pac_hexnew)
            self.layout2.addWidget(splitter1)
            layout.addWidget(splitter)
            centralwidget1.setLayout(layout)
            self.setCentralWidget(centralwidget1)

    def statistics(self):
        """
        弹出统计窗口报文
        :return:None
        """
        self.static_win = ApplicationWindow()
        self.static_win.show()
        _thread.start_new_thread(set_cap, (self.sni, self.static_win))

    def keyReleaseEvent(self, event):
        """
        键盘选中信息事件
        :param event: 键盘点击事件
        :return: None
        """
        try:
            if event.key() == Qt.Key_Up or event.key() == Qt.Key_Down:
                self.correctid = self.info_treeWidget.currentItem().text(0)
                if self.correctid and self.correctid.isdigit():
                    self.correctid = int(self.correctid)
                    self.select_packet = self.sni.get_packet_by_id(self.correctid)
                    if self.select_packet == "Error":
                        reply = QMessageBox.critical(self, "错误", "没有找到该分组，请稍等！", QMessageBox.Close)
                        if reply == QMessageBox.Close:
                            return
                    else:
                        a = []
                        self.layer = self.sni.get_detailed_packet(self.select_packet, a, self.correctid)
                        if self.layer == "Error":
                            reply = QMessageBox.critical(self, "错误", "没有分析出该分组，请稍等！", QMessageBox.Close)
                            if reply == QMessageBox.Close:
                                return
                        else:
                            self.info_pack.clear()
                            self.pac_hexnew.clear()
                            self.read_layer(self.layer)
                            hexstr = self.sni.get_hexdump(self.select_packet)
                            self.pac_hexnew.setPlainText(hexstr)
        except:
            pass

    def center_win(self):
        """
        将窗口放在屏幕正中
        :return: None
        """
        screen = QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move((screen.width() - size.width()) / 4,
                  (screen.height() - size.height()) / 4)

    def info_tree_check(self):
        if self.tree_no.isChecked():
            self.info_treeWidget.setColumnHidden(0, False)
        else:
            self.info_treeWidget.setColumnHidden(0, True)
        if self.tree_time.isChecked():
            self.info_treeWidget.setColumnHidden(1, False)
        else:
            self.info_treeWidget.setColumnHidden(1, True)
        if self.tree_source.isChecked():
            self.info_treeWidget.setColumnHidden(2, False)
        else:
            self.info_treeWidget.setColumnHidden(2, True)
        if self.tree_destination.isChecked():
            self.info_treeWidget.setColumnHidden(3, False)
        else:
            self.info_treeWidget.setColumnHidden(3, True)
        if self.tree_protocol.isChecked():
            self.info_treeWidget.setColumnHidden(4, False)
        else:
            self.info_treeWidget.setColumnHidden(4, True)
        if self.tree_length.isChecked():
            self.info_treeWidget.setColumnHidden(5, False)
        else:
            self.info_treeWidget.setColumnHidden(5, True)
        if self.tree_info.isChecked():
            self.info_treeWidget.setColumnHidden(6, False)
        else:
            self.info_treeWidget.setColumnHidden(6, True)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    mywiredolphin = Wiredolphin()
    mywiredolphin.show()
    sys.exit(app.exec())
