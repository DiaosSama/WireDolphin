# done test
def _get_bin(target):
        if not target.isdigit():
            raise Exception('bad ip address')
        target = int(target)
        assert target < 256, 'bad ip address'
        res = ''
        temp = target
        for t in range(8):
            a, b = divmod(temp, 2)
            temp = a
            res += str(b)
            if temp == 0:
                res += '0' * (7 - t)
                break
        return res[::-1]

# done test 
def ipv4_32(ipv4_address):
        temp_list = ipv4_address.split('.')
        assert len(temp_list) == 4, 'bad ip address'
        return ''.join(list(map(_get_bin, temp_list)))


# done test
def match_net(ip,net=[],n=0):
    """
    查看一个ip是否在一个子网里面   
    ip:ip;
    net:在指定子网的一个ip
    n: 子网长度； 192.168.56.1/n
    """
    if len(net)==0:
        return True
    if ':' in ip:## ipv6地址，不进行判断
        return False
    ip_line = ipv4_32(ip)
    net_line = ipv4_32(net[0])[:32 -n]
    if net_line == ip_line[:32-n]:
        return True
    else:
        return False
# done test
def match_dfnet(ips,net=[],n=0):
    re=[]
    if len(net)==0:
        return [True for i in range(len(ips))]
    for ip in ips:
        re.append(match_net(ip,net,n))
    return re



