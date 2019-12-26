import psutil
from psutil import net_if_addrs

class infaceinnfo():
    def __init__(self, mac="None", ip4="None", ip6="None"):
        self.mac = mac
        self.ip4 = ip4
        self.ip6 = ip6

    def get_mac(self):
        return self.mac

    def get_ip4(self):
        return self.ip4

    def get_ip6(self):
        return self.ip6


# 获取网卡名称和其IPV6地址
def get_cardipv6():
    rs = {}
    for k, v in net_if_addrs().items():
        for item in v:
            address = item[1]
            if ':' in address:
                rs[k] = address
    return rs


# 获取网卡名称和其mac地址，不包括回环
def get_cardmac():
    rs = {}
    for k, v in net_if_addrs().items():
        rs[k] = "None"
        for item in v:
            address = item[1]
            if '-' in address and len(address) == 17:
                rs[k] = address
    return rs


# 获取网卡名称和其ip地址，不包括回环
def get_cardipv4():
    rs = {}
    info = psutil.net_if_addrs()
    for k, v in info.items():
        '''
                for item in v:
            if item[0] == 2 and not item[1] == '127.0.0.1':
                rs[k]=item[1]
        '''
        for item in v:
            if item[0] == 2:
                rs[k] = item[1]
    return rs


def __check_speeds():
    rs = {}
    info = psutil.net_if_stats()
    for k, v in info.items():
        rs[k] = v.speed
    return rs


def __snapshoot():
    rs = {}
    for net_name, counters in psutil.net_io_counters(pernic=True).items():
        rs[net_name] = counters.bytes_recv
    return rs


def union_inface(mac, ip4, ip6):
    rs = {}
    key_list = list(mac.keys())
    for i in key_list:
        inface = infaceinnfo(mac[i], ip4[i], ip6[i])
        rs[i] = inface
    return rs
