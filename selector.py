import pandas as pd
import select_funcsions as fs
import jd_functions as jd


# 1.	proto：包使用的网络协议；
# 2.	ip.s：包的源地址；
# 3.	ip.d：包的目的地址；
# 4.	port.s：包的源端口；
# 5.	port.d：包的目的端口；
# 6.	net.s：源ip所在的子网；
# 7.	net.d：目的ip所在的子网；
# 8.	len：包的长度；

def net_op(value):
    if len(value) == 0:
        return [], 0
    else:
        return value[0], value[1]


def kv_jd(key, value):
    """
    判断某个关键词的输入值是否正确
    key: 关键词
    value : 关键词key对应的输入值
    return: 如果输入值合法，会返回输入值；
        如果输入值不合法，返回False。
    """
    if key == "proto":
        return jd.proto(value)

    if key == "ip.s":
        return jd.src_ip(value)

    if key == "port.s":
        return jd.src_port(value)

    if key == "ip.d":
        return jd.des_ip(value)

    if key == "port.d":
        return jd.des_port(value)

    if key == "net.s":
        subs = value.split('/')
        if len(subs) != 2:
            return False
        n = jd.src_net_n(subs[1])
        net_s = jd.src_net(subs[0])

        if n == False or net_s == False:
            return False
        return [net_s, n]

    if key == "net.d":
        subs = value.split('/')
        if len(subs) != 2:
            return False
        n = jd.des_net_n(subs[1])
        net_d = jd.des_net(subs[0])

        if n == False or net_d == False:
            return False
        return [net_d, n]

    if key == "len":
        return jd.pk_len(value)

    return False


def sl_jd(jd_str):
    """
    判断一个字符串是否符合过滤语法；
    jd_str: 过滤语法的输入字符串
    return: 如果输入语法正确，返回过滤语法解析结果，类型是一个字典
        如果输入语法不和法，返回False
    
    """

    paras = {"proto": [],
             "ip.s": [],
             "ip.d": [],
             "port.s": [],
             "port.d": [],
             "net.s": [],
             "net.d": [],
             "len": []
             }
    # 查找属性值
    if jd_str == "":
        return paras
    attrs = jd_str.split(' ')
    if len(attrs) == 0:
        return paras
    for attr in attrs:
        # 属性赋值句子是否正确
        sub_attrs = attr.split("==")
        if len(sub_attrs) != 2:
            return False
        else:
            key = sub_attrs[0]
            value = sub_attrs[1]
            # 判断属性值是否正确
            x = kv_jd(key, value)
            if x != False:
                paras[key] = x
            else:
                return False

    if len(paras['net.s']) == 2 and len(paras['net.s'][0]) < 1:
        return False
    if len(paras['net.d']) == 2 and len(paras['net.d'][0]) < 1:
        return False

    return paras


# doen test
def init(packetlist=[]):
    """
    将packetlist 中得数据形式转为df(pd.DataFrame)
    return df  
    """
    df = pd.DataFrame(packetlist)
    return df


# done test
def select(packetlist=[], jd=dict()):
    """
    包过滤函数,选择符合条件得包和包的序列号

    packetlist: 未经筛选的包的列表

    jd： 一个筛选条件的字典
    
    return: 返回筛选符合调节的包的No和包，以列表返回；
        如果运行出现错误，返回2个值，是原来的包列表和False
    
   """
    if len(packetlist) == 0:
        return [], []

    try:
        proto = jd["proto"]
        Src_ips = jd["ip.s"]
        port_s = jd["port.s"]
        Des_ips = jd["ip.d"]
        port_d = jd["port.d"]
        l = jd["len"]
        net_s_ip, net_s_n = net_op(jd["net.s"])
        net_d_ip, net_d_n = net_op(jd["net.d"])

    except:
        return False, packetlist

    df = pd.DataFrame(packetlist)

    x2 = []
    for x in packetlist:
        x2.append([x])

    df2 = pd.DataFrame(x2)
    select_df1 = df[(df["Proto"].isin(proto) | (len(proto) == 0))
                    & (df["Src"].isin(Src_ips) | (len(Src_ips) == 0))
                    & (df["Dst"].isin(Des_ips) | (len(Des_ips) == 0))
                    & (df["Sport"].isin(port_s) | (len(port_s) == 0))
                    & (df["Dport"].isin(port_d) | (len(port_d) == 0))
                    & (df["Len"].isin(l) | (len(l) == 0))
                    & fs.match_dfnet(df["Src"], net_s_ip, net_s_n)
                    & fs.match_dfnet(df["Dst"], net_d_ip, net_d_n)
                    ]
    select_df2 = df2[(df["Proto"].isin(proto) | (len(proto) == 0))
                     & (df["Src"].isin(Src_ips) | (len(Src_ips) == 0))
                     & (df["Dst"].isin(Des_ips) | (len(Des_ips) == 0))
                     & (df["Sport"].isin(port_s) | (len(port_s) == 0))
                     & (df["Dport"].isin(port_d) | (len(port_d) == 0))
                     & (df["Len"].isin(l) | (len(l) == 0))
                     & fs.match_dfnet(df["Src"], net_s_ip, net_s_n)
                     & fs.match_dfnet(df["Dst"], net_d_ip, net_d_n)
                     ]

    re_1 = list(select_df1["No"].values)

    values = select_df2.values

    re_2 = []
    for x in values:
        re_2.append(x[0])
    return re_1, re_2


def select_no(packetlist=[], jd=dict()):
    """
    包过滤函数,选择符合条件得包和包的序列号

    packetlist: 未经筛选的包的列表

    jd： 一个筛选条件的字典
    
    return: 返回筛选符合条件包的NO，以列表返回；
        如果运行出现错误，只有一个返回值: False
    
    """
    if len(packetlist) == 0:
        return []

    try:
        proto = jd["proto"]
        Src_ips = jd["ip.s"]
        port_s = jd["port.s"]
        Des_ips = jd["ip.d"]
        port_d = jd["port.d"]
        l = jd["len"]
        net_s_ip, net_s_n = net_op(jd["net.s"])
        net_d_ip, net_d_n = net_op(jd["net.d"])

    except:
        return False

    df = pd.DataFrame(packetlist)

    x2 = []
    for x in packetlist:
        x2.append([x])

    df2 = pd.DataFrame(x2)
    select_df1 = df[(df["Proto"].isin(proto) | (len(proto) == 0))
                    & (df["Src"].isin(Src_ips) | (len(Src_ips) == 0))
                    & (df["Dst"].isin(Des_ips) | (len(Des_ips) == 0))
                    & (df["Sport"].isin(port_s) | (len(port_s) == 0))
                    & (df["Dport"].isin(port_d) | (len(port_d) == 0))
                    & (df["Len"].isin(l) | (len(l) == 0))
                    & fs.match_dfnet(df["Src"], net_s_ip, net_s_n)
                    & fs.match_dfnet(df["Dst"], net_d_ip, net_d_n)
                    ]

    re_1 = list(select_df1["No"].values)

    return re_1


def select_pk(packetlist=[], jd=dict()):
    """
    包过滤函数,选择符合条件得包和包的序列号

    packetlist: 未经筛选的包的列表

    jd： 一个筛选条件的字典
    
    return: 返回筛选符合条件的包，以列表返回；
        如果运行出现错误，只有一个返回值，是False
    
    """
    if len(packetlist) == 0:
        return []

    try:
        proto = jd["proto"]
        Src_ips = jd["ip.s"]
        port_s = jd["port.s"]
        Des_ips = jd["ip.d"]
        port_d = jd["port.d"]
        l = jd["len"]
        net_s_ip, net_s_n = net_op(jd["net.s"])
        net_d_ip, net_d_n = net_op(jd["net.d"])

    except:
        return False

    df = pd.DataFrame(packetlist)

    x2 = []
    for x in packetlist:
        x2.append([x])

    df2 = pd.DataFrame(x2)
    select_df2 = df2[(df["Proto"].isin(proto) | (len(proto) == 0))
                     & (df["Src"].isin(Src_ips) | (len(Src_ips) == 0))
                     & (df["Dst"].isin(Des_ips) | (len(Des_ips) == 0))
                     & (df["Sport"].isin(port_s) | (len(port_s) == 0))
                     & (df["Dport"].isin(port_d) | (len(port_d) == 0))
                     & (df["Len"].isin(l) | (len(l) == 0))
                     & fs.match_dfnet(df["Src"], net_s_ip, net_s_n)
                     & fs.match_dfnet(df["Dst"], net_d_ip, net_d_n)
                     ]

    values = select_df2.values
    re_2 = []
    for x in values:
        re_2.append(x[0])
    return re_2
