import psutil
from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QSizePolicy
from matplotlib.backends.backend_template import FigureCanvas
from inface import *
import _thread
import sys
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.uic.properties import QtWidgets
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt
from PyQt5.QtCore import QTimer
import random
import numpy as np
import time
import threading
from PyQt5 import QtWidgets, QtCore
from inface import *

class PlotCanvas(FigureCanvas):

    def __init__(self, parent=None,width=4, height=0.1, dpi=100, inface="WLAN"):
        self.interface = inface
        self.fig = plt.Figure(figsize=(width, height), dpi=dpi)
        self.axes = self.fig.add_subplot(111, frameon=False)
        plt.axis('off')
        self.axes.cla()
        self.axes.set_xticks([])
        self.axes.set_yticks([])
        FigureCanvas.__init__(self, self.fig)
        self.setParent(parent)


        FigureCanvas.setSizePolicy(self, QSizePolicy.Expanding, QSizePolicy.Expanding)
        FigureCanvas.updateGeometry(self)
        self.init_plot()  # 打开App时可以初始化图片
        #self.plot()
        a=threading.Thread(target=self.update_figure, daemon=True)
        a.start()

    def plot(self):
        timer = QTimer(self)
        timer.timeout.connect(self.update_figure)
        timer.start(100)

    def init_plot(self):
        self.axes.cla()
        self.x = []
        self.y = []
        self.i = 0
        plt.axis('off')
        self.axes.set_xticks([])
        self.axes.set_yticks([])
        self.axes.plot(self.x, self.y)
        self.snap_prev = self.snapshoot()#新增

    def update_figure(self):
        while True:
            try:
                number = 0
                self.axes.cla()
                # self.snap_prev = self.snapshoot()
                self.snap_now = self.snapshoot()
                recv_prev = self.snap_prev[self.interface]
                recv_now = self.snap_now[self.interface]
                # rate = (recv_now - recv_prev) / (1024 * 1024 / 8)
                rate = (recv_now - recv_prev) / (1024 / 8)
                self.x.append(self.i)
                self.y.append(rate)
                # print(self.x)
                # print(self.y)
                if self.i < 20:
                    self.axes.plot(self.x, self.y)
                    self.axes.set_xticks([])
                    self.axes.set_yticks([])
                    self.draw()  # 注意此函数需要调用
                    self.i += 1
                else:
                    # self.fig.set_facecolor("#C1D2F0")
                    tmp = [j - 1 for j in self.x]
                    self.x = tmp.copy()
                    tmp.clear()
                    self.x.remove(self.x[0])
                    self.y.remove(self.y[0])
                    self.axes.plot(self.x, self.y)
                    self.axes.set_xticks([])
                    self.axes.set_yticks([])
                    self.draw()  # 注意此函数需要调用'''
                self.snap_prev = self.snap_now  # 新增
                time.sleep(0.1)
            except:
                return

    def snapshoot(self):
        rs = {}
        for net_name, counters in psutil.net_io_counters(pernic=True).items():
            rs[net_name] = counters.bytes_recv
        return rs


