#lastdata: 2019.11.26
#@author huangjingzhi 

# done test
def isip(ip_string=""):
    """
    # 判断一个字符窜是是合理的IP地址
    ip_string: 需要判断的ip字符串
    """

    if '.' in ip_string:# ipv4
        sub_address = ip_string.split('.')
        if len(sub_address)!=4:
            return False
        try:
            for sub in sub_address:
                if int(sub)>255 or int(sub)<0:
                    return False
            return True
        except:
            return False

    if ':' in  ip_string: # ipv6
        sub_address = ip_string.split(':')
        if len(sub_address)!= 8:
            return False
        for sub in sub_address:
            if len(sub)>4:
                return False
            for c in sub:
                if c not in ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']:
                    return False
        return True      

    return False

# done test
def proto(value):
    if value=="":
        return []
    base_protoes =["TCP", "TCPv6", "UDP", "UDPv6", "HTTP", "HTTPS", "DNS", "DNSv6",
                   "MDNS", "MDNSv6", "SSDP", "SSDPv6", "ICMP", "ICMPv6", "ARP"]
    prots = value.split(",")
    for prot in prots:
        if prot not in base_protoes:
            return False
    return prots


# done test
def src_ip(value):
    if value == "":
        return []
    
    re_ips = []
    ips = value.split(',')
    for ip in ips:
        if isip(ip):
            re_ips.append(ip)
        else:
            return False
    return re_ips

# done test
def des_ip(value):
    if value == "":
        return []
    
    re_ips = []
    ips = value.split(',')
    for ip in ips:
        if isip(ip):
            re_ips.append(ip)
        else:
            return False
    return re_ips


#done test
def des_port(value):
    re_portlist = []
    #print(type(value))
    if value=="":
        return re_portlist

    if '[' in value:
        if ']' in value:
            value = value[1:-1]
            sub_vs = value.split(',')
            
            if len(sub_vs) !=2:
                return False
            try:
                min_len = int(sub_vs[0])
                max_len = int(sub_vs[1])
                if min_len<0 :
                    return False

                re_portlist = [i for i in range(min_len, max_len+1)]
                return re_portlist
            except:
                return False
            
         
    sub_values = value.split(",")
    if len(sub_values)>1:
        try:
            for x in sub_values:
                re_portlist.append(int(x))
            return re_portlist
        except:
            return False


    ## 单个长度
    try:
        re_portlist.append(int(value))
        return re_portlist

    except:
        return False
    return False

#done test
def src_port(value):
    re_portlist = []
    #print(type(value))
    if value=="":
        return re_portlist

    if '[' in value:
        if ']' in value:
            value = value[1:-1]
            sub_vs = value.split(',')
            
            if len(sub_vs) !=2:
                return False
            try:
                min_len = int(sub_vs[0])
                max_len = int(sub_vs[1])
                if min_len<0 :
                    return False

                re_portlist = [i for i in range(min_len, max_len+1)]
                return re_portlist
            except:
                return False
            
         
    sub_values = value.split(",")
    if len(sub_values)>1:
        try:
            for x in sub_values:
                re_portlist.append(int(x))
            return re_portlist
        except:
            return False


    ## 单个长度
    try:
        re_portlist.append(int(value))
        return re_portlist

    except:
        return False
    return False

# done test
def src_net(value):
    if value=="":
        return []
    if isip(value):
        return [value]
    else:
        return False

#done test
def src_net_n(value):
    try:
        n = int(value)

        if n<0 or n>32:
            return False
        return n
    except:
        pass
    return False
  
#done test
def des_net(value):
    if value=="":
        return []
    if isip(value):
        return [value]
    else:
        return False

#done test
def des_net_n(value):
    try:
        n = int(value)

        if n<0 or n>32:
            return False
        return n
    except:
        pass
    return False
# done test
def pk_len(value=""):
    
    re_lenlist = []
    #print(type(value))
    if value=="" or len(value)==0:
        return re_lenlist

    if '[' in value:
        if ']' in value:
            value = value[1:-1]
            sub_vs = value.split(',')
            
            if len(sub_vs) !=2:
                return False
            try:
                min_len = int(sub_vs[0])
                max_len = int(sub_vs[1])
                if min_len<0 :
                    return False

                re_lenlist = [i for i in range(min_len, max_len+1)]
                return re_lenlist
            except:
                return False
            
         
    sub_values = value.split(",")
    if len(sub_values)>1:
        try:
            for x in sub_values:
                re_lenlist.append(int(x))
            return re_lenlist
        except:
            return False


    ## 单个长度
    try:
        re_lenlist.append(int(value))
        return re_lenlist

    except:
        return False
    return False

