import pandas as pd
import numpy as np
import sys
import os
import random
import _thread
import matplotlib.image as img
import time

from PyQt5 import QtCore, QtWidgets,QtGui
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QMenu, QVBoxLayout,QHBoxLayout, QSizePolicy, QWidget, QTextBrowser, QLineEdit
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from matplotlib.animation import FuncAnimation
import matplotlib.pyplot as plt


class MyMplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig = plt.figure(figsize=(width, height), dpi=dpi,edgecolor='b')
        self.fig.set_facecolor('azure')#画布背景色
        # 背景
        #bgimg = img.imread("echarts.png")
        #self.fig.figimage(bgimg,alpha=0.5,resize=False)
        
        self.ax = self.fig.add_subplot(1,1,1)
        FigureCanvas.__init__(self, self.fig)
        self.setParent(parent)
        FigureCanvas.setSizePolicy(self,
                                   QtWidgets.QSizePolicy.Expanding,
                                   QtWidgets.QSizePolicy.Expanding)
        FigureCanvas.updateGeometry(self)


class ApplicationWindow(QtWidgets.QMainWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        self.setWindowIcon(QIcon('img_source/dolphin.ico'))
        self.setWindowFlag(QtCore.Qt.MSWindowsFixedSizeDialogHint)
        self.iner_cs = ["peru","b","aqua","lime","cornflowerblue","grey","red","gold","pink"]
        cs_index = ["tcp1","tcp2","tcp3","tcp4","tcp5","tcp6","tcp7","tcp8","tcp9"]
        cs_ser = pd.Series(data=self.iner_cs,index=cs_index)
        serr = pd.Series(index=cs_index,data=[1,2,3,4,5,6,7,8,9])
        
        self.cs = self.iner_cs[:]
        self.cs_index = cs_index
        self.cs_serr =cs_ser
        self.serr = serr
        self.df = pd.DataFrame()
        self.is_stop = False

        self.setAttribute(QtCore.Qt.WA_DeleteOnClose)
        self.setWindowTitle("报文数据统计")
        self.main_widget = QtWidgets.QWidget(self)
        self.resize(1200,950)
        self.canvas_barh =  MyMplCanvas( self.main_widget,width=6, height=6, dpi=100) ###attention###
        self.canvas_pie = MyMplCanvas( self.main_widget,width=6, height=6, dpi=100) ## attention ###
        self.canvas_plt = MyMplCanvas( self.main_widget,width=6, height=6, dpi=100)
        
        self.canvas_barh.setGeometry(QtCore.QRect(450, 550, 780, 400))
        self.canvas_pie.setGeometry(QtCore.QRect(20, 550, 400, 400))
        self.canvas_plt.setGeometry(QtCore.QRect(0, 130, 1300, 400))
        hbox = QtWidgets.QHBoxLayout(self.main_widget)
    
        self.main_widget.setFocus()
        self.setCentralWidget(self.main_widget)




        font = QtGui.QFont()
        font.setFamily("AcadEref")
        font.setPointSize(9)
        #MainWindow.setFont(font)

        font = QtGui.QFont()
        font.setPointSize(21)

        self.lineEdit = QtWidgets.QLineEdit(self.main_widget)
        self.lineEdit.setGeometry(QtCore.QRect(500,0, 321, 50))
        self.lineEdit.setFont(font)
        self.lineEdit.setStyleSheet("background:transparent;border-width:0;border-style:outset")
        self.lineEdit.setObjectName("lineEdit")
        self.lineEdit.setText("报 文 数 据 统 计")

        font2 = QtGui.QFont()
        font2.setFamily("AcadEref")
        font2.setPointSize(9)
        #MainWindow.setFont(font)

        font2 = QtGui.QFont()
        font2.setPointSize(10)


        self.TCP_lineEdit = QtWidgets.QLineEdit(self.main_widget)
        self.TCP_lineEdit.setGeometry(QtCore.QRect(100,70, 100, 50))
        self.TCP_lineEdit.setFont(font2)
        self.TCP_lineEdit.setStyleSheet("background:transparent;border-width:0;border-style:outset")
        self.TCP_lineEdit.setObjectName("lineEdit")
        self.TCP_lineEdit.setText("TCP:0")


        self.UDP_lineEdit = QtWidgets.QLineEdit(self.main_widget)
        self.UDP_lineEdit.setGeometry(QtCore.QRect(200,70, 100, 50))
        self.UDP_lineEdit.setFont(font2)
        self.UDP_lineEdit.setStyleSheet("background:transparent;border-width:0;border-style:outset")
        self.UDP_lineEdit.setObjectName("lineEdit")
        self.UDP_lineEdit.setText("UDP:0")


        self.ARP_lineEdit = QtWidgets.QLineEdit(self.main_widget)
        self.ARP_lineEdit.setGeometry(QtCore.QRect(300,70, 100, 50))
        self.ARP_lineEdit.setFont(font2)
        self.ARP_lineEdit.setStyleSheet("background:transparent;border-width:0;border-style:outset")
        self.ARP_lineEdit.setObjectName("lineEdit")
        self.ARP_lineEdit.setText("ARP:0")


        self.IPv4_lineEdit = QtWidgets.QLineEdit(self.main_widget)
        self.IPv4_lineEdit.setGeometry(QtCore.QRect(400,70, 100, 50))
        self.IPv4_lineEdit.setFont(font2)
        self.IPv4_lineEdit.setStyleSheet("background:transparent;border-width:0;border-style:outset")
        self.IPv4_lineEdit.setObjectName("lineEdit")
        self.IPv4_lineEdit.setText("IPv4:0")

        self.IPv6_lineEdit = QtWidgets.QLineEdit(self.main_widget)
        self.IPv6_lineEdit.setGeometry(QtCore.QRect(500,70, 100, 50))
        self.IPv6_lineEdit.setFont(font2)
        self.IPv6_lineEdit.setStyleSheet("background:transparent;border-width:0;border-style:outset")
        self.IPv6_lineEdit.setObjectName("lineEdit")
        self.IPv6_lineEdit.setText("IPv6:0")


        self.stop_button = QtWidgets.QPushButton(self.main_widget)
        self.stop_button.setGeometry(QtCore.QRect(1000, 65,100 , 31))
        self.stop_button.setObjectName("control")
        self.stop_button.setText("停止统计")
        self.stop_button.clicked.connect(self.flush_control)

        #self.setStyleSheet("background-color:white")
        #self.setStyleSheet("background-color:lightsteelblue")
        self.setStyleSheet("background-color:lightblue")#窗口背景色
        #self.setStyleSheet("background-color:aliceblue")#窗口背景色

    def flush_control(self):

        if self.is_stop ==False:
            self.is_stop=True
            self.stop_button.setText("继续统计")
        else:
            self.is_stop =False   
            self.stop_button.setText("停止统计")

    def update_line(self):
        if self.is_stop:
            return
        
        serr = self.serr
        self.pie(serr)
        self.barh(serr)
        
        df =self.df
        #for i in range(100):
        #    serr["tcp6"] = i+ 100
        #    serr["tcp5"] = 55 + 100
        #    df = df.append(serr,ignore_index=True)
        self.plot(df)
        
   
    def set_serr(self,serr_in=pd.Series()):
        self.cs = self.iner_cs[:len(serr_in)]############
        self.serr = serr_in.copy()
        self.cs_index = self.serr.index##################
        self.cs_index = self.serr.index
        self.cs_serr = pd.Series(data=self.cs,index=self.cs_index)

        self.TCP_lineEdit.setText("TCP: " + str(serr_in["TCP"]))
        self.UDP_lineEdit.setText("UDP: " + str(serr_in["UDP"]))
        self.ARP_lineEdit.setText("ARP: " + str(serr_in["ARP"]))
        self.IPv4_lineEdit.setText("IPv4: " + str(serr_in["IPv4"]))
        self.IPv6_lineEdit.setText("IPv6: " + str(serr_in["IPv6"]))

        self.df = self.df.append(serr_in.copy(),ignore_index=True)
        if len(self.df)>10000:
            self.df = self.df.drop(index=self.df.index[0],axis=0)
   
    def pie(self,serr = pd.Series()):
        
        self.canvas_pie.ax.clear()
        recipe = serr.index  
        data = serr.values
        cs_ser = self.cs_serr
        iner_cs = cs_ser.loc[recipe]
        explode=[0.005 for x in range(len(data))]
        self.canvas_pie.ax.pie(x=data,labels=recipe,autopct='%.1f%%',
                explode=explode,colors=iner_cs,wedgeprops=dict(width=0.6),
                #wedgeprops={'linewidth':1.5,'edgecolor':'black'},
                textprops={'fontsize':10,'color':'black'}
                )
        #self.canvas_pie.ax.axesPatch.set_alpha(0.05)    
        self.canvas_pie.ax.set_title("Message pie chart statistics",loc='center', fontsize='20')
        self.canvas_pie.fig.canvas.draw_idle()

    def barh(self, serr):
        self.canvas_barh.ax.clear()
        serr = serr.sort_values(ascending=True)
        # 中文乱码和坐标轴负号处理。
        #matplotlib.rc('font', family='SimHei', weight='bold')
        #plt.rcParams['axes.unicode_minus'] = False 
        index = list(serr.index)
        data = []

        cs_ser = self.cs_serr
        iner_cs = cs_ser.loc[index]

        data = serr.values
        #绘图。
        self.canvas_barh.ax.patch.set_alpha(0.05)

        b =self.canvas_barh.ax.barh(range(len(index)), data, color=iner_cs,tick_label=index) #为横向水平的柱图右侧添加数据标签。
        for rect in b:
            w = rect.get_width()
            self.canvas_barh.ax.text(w, rect.get_y()+rect.get_height()/2, '%d' % int(w), ha='left', va='center') 
        #设置Y轴纵坐标上的刻度线标签。
        self.canvas_barh.ax.set_yticks(range(len(index)))
        self.canvas_barh.ax.set_yticklabels(index) 
        #不要X横坐标上的label标签。 
        self.canvas_barh.ax.set_title('Message histogram statistics', loc='center', fontsize='20')
        self.canvas_barh.fig.canvas.draw_idle()

    def plot(self, df=pd.DataFrame()):
        cs_index =self.cs_index
        cs = self.cs     
        self.canvas_plt.ax.clear()

        for index in cs_index:
            self.canvas_plt.ax.plot(df[index],c=self.cs_serr[index])
        #self.canvas_plt.ax.plot(df)

        self.canvas_plt.ax.set_xlabel('time/s')
        self.canvas_plt.ax.set_ylabel('number')
        self.canvas_plt.ax.set_title('Message discount statistics',loc='center', fontsize='20')

        self.canvas_plt.ax.set_xlim(xmin=df.index[0],xmax=df.index[-1] + 50)

        self.canvas_plt.ax
        self.canvas_plt.ax.legend(cs_index,loc="upper right")
        self.canvas_plt.ax.patch.set_alpha(0.05)
        self.canvas_plt.fig.canvas.draw_idle()

def set_cap(cap,aw):
    #cap: Capture 实例对象
    #aw: ApplicationWindow():统计窗口对象
    # 函数功能：在子线程中运行，将统计窗口与抓取报文的对象绑定，定时刷新
    while True:
        try:
            serr = pd.Series(cap.counter)
            aw.set_serr(serr)
            aw.update_line()
            time.sleep(1)
        except:
            return