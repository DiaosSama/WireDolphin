from scapy.all import *
from tempfile import TemporaryFile
import threading
import string
import random
import time
import os


class Capture:
    """
    报文抓取类，支持的协议类型：IPv4/6, TCP, UDP, HTTP(S), DNS, MDNS, SSDP, ICMP
    Create by DiaosSama
    """
    def __init__(self, iface):
        """
        初始化抓包类
        :param iface: 用于抓包的网卡
        """
        # e.g.[{"No":1, "Time":16.002313, "Src":"127.0.0.1", "Dst":"127.0.0.1, "Proto":"TCP", "Len":92, "Info":summary}]
        self.packetlist = []
        # 网卡NIC
        self.iface = iface
        # 暂停标志
        self.pauseflag = False
        # 停止标志
        self.stopflag = True
        # 开始标志
        self.startflag = False
        # 文件加载标志
        self.loadflag = False
        # 临时文件名称
        # temp = TemporaryFile(suffix=".pcap",
        #                      prefix=''.join(random.sample(string.ascii_letters, 8)),
        #                      delete=False)
        # self.tempname = temp.name
        # temp.close()
        self.tempname = None
        # 包序号
        self.packetid = 0
        # 起始时间戳
        self.starttime = 0
        # 计数器
        self.counter = {"IPv4": 0, "IPv6": 0, "ARP": 0, "TCP": 0, "UDP": 0}
        # 临时文件名缓存
        self.temp_list = list()
        # self.temp_list.append(self.tempname)
        # 文件Writer
        self.writer = None

    def _capture(self):
        # append=True代表追加至临时文件中
        # writer = PcapWriter(self.tempname, append=True, sync=True)
        # stop_filter指定sniff()停止条件
        sniff(iface=self.iface,
              store=False,
              prn=lambda pkt: self._analyze_packet(pkt),
              stop_filter=lambda pkt: self.stopflag)
        self.writer.close()
        # writer.close()

    def _clean(self):
        """
        清空所有临时变量
        """
        # 清除原临时文件
        try:
            for name in self.temp_list:
                os.remove(name)
                self.temp_list.remove(name)
        except:
            # 防止captrue线程占用tempfile导致访问失败
            print("_clean failed")
            time.sleep(0.5)
            self._clean()
        else:
            # self.tempname = TemporaryFile(suffix=".pcap",
            #                               prefix=''.join(random.sample(string.ascii_letters, 8)),
            #                               delete=False).name
            self.tempname = None
            # 清空临时包摘要表
            self.packetlist = []
            # 清空计数器
            for i in self.counter:
                self.counter[i] = 0
            # 清空包序号
            self.packetid = 0
            # 清空起始时间
            self.starttime = 0
            # 清空临时文件名缓存
            self.temp_list = list()
            # self.temp_list.append(self.tempname)

    def _analyze_packet(self, pkt, writer=None):
        if (self.pauseflag or self.stopflag) and (not isinstance(writer, str)):
            return
        if (self.packetid % 1000 == 0) and (not isinstance(writer, str)):
            # 临时文件名称
            tempname = ''.join(random.sample(string.ascii_letters, 8))
            # 防止随机文件名冲突
            while tempname in self.temp_list:
                tempname = ''.join(random.sample(string.ascii_letters, 8))
            temp = TemporaryFile(suffix=".pcap",
                                 prefix=tempname,
                                 delete=False)
            self.tempname = temp.name
            temp.close()
            # 临时文件名追加至缓存中
            self.temp_list.append(self.tempname)
            # 关闭self.writer
            if self.writer:
                self.writer.close()
            # append=True代表追加至临时文件中
            self.writer = PcapWriter(self.tempname, append=True, sync=True)
        if not isinstance(writer, str):
            writer = self.writer
        # 以太帧
        if pkt.name == "Ethernet":
            mac_src = pkt.src
            mac_dst = pkt.dst
            ether_payload = pkt.payload

            # IPv4报文
            if ether_payload.name == "IP":
                ip_src = ether_payload.src
                ip_dst = ether_payload.dst
                ip_payload = ether_payload.payload
                self.counter["IPv4"] += 1

                # TCP报文
                if ip_payload.name == "TCP":
                    sport = ip_payload.sport
                    dport = ip_payload.dport
                    self.counter["TCP"] += 1

                    # HTTP
                    if sport == 80 or dport == 80:
                        proto = "TCP"
                        try:
                            load = bytes.decode(ip_payload.payload.load)
                            line = load.split("\r\n")
                            for i in line:
                                if "HTTP" in i:
                                    proto = "HTTP"
                                    break
                        except Exception:
                            pass
                        finally:
                            self.packetid += 1
                            packet = self._create_summary(self.packetid,
                                                          self._get_timestamp(pkt),
                                                          ip_src,
                                                          ip_dst,
                                                          proto,
                                                          len(pkt),
                                                          pkt.summary(),
                                                          sport,
                                                          dport)
                            self.packetlist.append(packet)

                    # HTTPS
                    elif sport == 443 or dport == 443:
                        proto = "TCP"
                        try:
                            load = bytes.decode(ip_payload.payload.load)
                            line = load.split("\r\n")
                            for i in line:
                                if "HTTPS" in i:
                                    proto = "HTTPS"
                                    break
                        except Exception:
                            pass
                        finally:
                            self.packetid += 1
                            packet = self._create_summary(self.packetid,
                                                          self._get_timestamp(pkt),
                                                          ip_src,
                                                          ip_dst,
                                                          proto,
                                                          len(pkt),
                                                          pkt.summary(),
                                                          sport,
                                                          dport)
                            self.packetlist.append(packet)

                    # 不属于HTTP/HTTPS
                    else:
                        self.packetid += 1
                        packet = self._create_summary(self.packetid,
                                                      self._get_timestamp(pkt),
                                                      ip_src,
                                                      ip_dst,
                                                      "TCP",
                                                      len(pkt),
                                                      pkt.summary(),
                                                      sport,
                                                      dport)
                        self.packetlist.append(packet)
                    if not isinstance(writer, str):
                        writer.write(pkt)

                # UDP报文
                elif ip_payload.name == "UDP":
                    sport = ip_payload.sport
                    dport = ip_payload.dport
                    self.counter["UDP"] += 1

                    # DNS
                    if sport == 53 or dport == 53:
                        self.packetid += 1
                        packet = self._create_summary(self.packetid,
                                                      self._get_timestamp(pkt),
                                                      ip_src,
                                                      ip_dst,
                                                      "DNS",
                                                      len(pkt),
                                                      pkt.summary(),
                                                      sport,
                                                      dport)
                        self.packetlist.append(packet)

                    # MDNS
                    elif sport == 5353 or dport == 5353:
                        self.packetid += 1
                        packet = self._create_summary(self.packetid,
                                                      self._get_timestamp(pkt),
                                                      ip_src,
                                                      ip_dst,
                                                      "MDNS",
                                                      len(pkt),
                                                      pkt.summary(),
                                                      sport,
                                                      dport)
                        self.packetlist.append(packet)

                    # SSDP
                    elif sport == 900 or dport == 1900:
                        self.packetid += 1
                        packet = self._create_summary(self.packetid,
                                                      self._get_timestamp(pkt),
                                                      ip_src,
                                                      ip_dst,
                                                      "SSDP",
                                                      len(pkt),
                                                      pkt.summary(),
                                                      sport,
                                                      dport)
                        self.packetlist.append(packet)

                    # 不属于以上三种协议
                    else:
                        self.packetid += 1
                        packet = self._create_summary(self.packetid,
                                                      self._get_timestamp(pkt),
                                                      ip_src,
                                                      ip_dst,
                                                      "UDP",
                                                      len(pkt),
                                                      pkt.summary(),
                                                      sport,
                                                      dport)
                        self.packetlist.append(packet)
                    if not isinstance(writer, str):
                        writer.write(pkt)

                # ICMP报文
                elif ip_payload.name == "ICMP":
                    self.packetid += 1
                    packet = self._create_summary(self.packetid,
                                                  self._get_timestamp(pkt),
                                                  ip_src,
                                                  ip_dst,
                                                  "ICMP",
                                                  len(pkt),
                                                  pkt.summary(),
                                                  -1,
                                                  -1)
                    self.packetlist.append(packet)
                    if not isinstance(writer, str):
                        writer.write(pkt)

                # 不属于以上三种协议
                else:
                    return
            # IPv6报文
            elif ether_payload.name == "IPv6":
                ip_src = ether_payload.src
                ip_dst = ether_payload.dst
                ip_payload = ether_payload.payload
                self.counter["IPv6"] += 1

                # TCP报文
                if ip_payload.name == "TCP":
                    sport = ip_payload.sport
                    dport = ip_payload.dport
                    self.counter["TCP"] += 1

                    # HTTP
                    if sport == 80 or dport == 80:
                        proto = "TCPv6"
                        try:
                            load = bytes.decode(ip_payload.payload.load)
                            line = load.split("\r\n")
                            for i in line:
                                if "HTTP" in i:
                                    proto = "HTTP"
                                    break
                        except Exception:
                            pass
                        finally:
                            self.packetid += 1
                            packet = self._create_summary(self.packetid,
                                                          self._get_timestamp(pkt),
                                                          ip_src,
                                                          ip_dst,
                                                          proto,
                                                          len(pkt),
                                                          pkt.summary(),
                                                          sport,
                                                          dport)
                            self.packetlist.append(packet)

                    # HTTPS
                    elif sport == 443 or dport == 443:
                        proto = "TCPv6"
                        try:
                            load = bytes.decode(ip_payload.payload.load)
                            line = load.split("\r\n")
                            for i in line:
                                if "HTTPS" in i:
                                    proto = "HTTPS"
                                    break
                        except Exception:
                            pass
                        finally:
                            self.packetid += 1
                            packet = self._create_summary(self.packetid,
                                                          self._get_timestamp(pkt),
                                                          ip_src,
                                                          ip_dst,
                                                          proto,
                                                          len(pkt),
                                                          pkt.summary(),
                                                          sport,
                                                          dport)
                            self.packetlist.append(packet)

                    # 不属于HTTP/HTTPS
                    else:
                        self.packetid += 1
                        packet = self._create_summary(self.packetid,
                                                      self._get_timestamp(pkt),
                                                      ip_src,
                                                      ip_dst,
                                                      "TCPv6",
                                                      len(pkt),
                                                      pkt.summary(),
                                                      sport,
                                                      dport)
                        self.packetlist.append(packet)
                    if not isinstance(writer, str):
                        writer.write(pkt)

                # UDP报文
                elif ip_payload.name == "UDP":
                    sport = ip_payload.sport
                    dport = ip_payload.dport
                    self.counter["UDP"] += 1

                    # DNS
                    if sport == 53 or dport == 53:
                        self.packetid += 1
                        packet = self._create_summary(self.packetid,
                                                      self._get_timestamp(pkt),
                                                      ip_src,
                                                      ip_dst,
                                                      "DNSv6",
                                                      len(pkt),
                                                      pkt.summary(),
                                                      sport,
                                                      dport)
                        self.packetlist.append(packet)

                    # MDNS
                    if sport == 5353 or dport == 5353:
                        self.packetid += 1
                        packet = self._create_summary(self.packetid,
                                                      self._get_timestamp(pkt),
                                                      ip_src,
                                                      ip_dst,
                                                      "MDNSv6",
                                                      len(pkt),
                                                      pkt.summary(),
                                                      sport,
                                                      dport)
                        self.packetlist.append(packet)

                    # SSDP
                    elif sport == 1900 or dport == 1900:
                        self.packetid += 1
                        packet = self._create_summary(self.packetid,
                                                      self._get_timestamp(pkt),
                                                      ip_src,
                                                      ip_dst,
                                                      "SSDPv6",
                                                      len(pkt),
                                                      pkt.summary(),
                                                      sport,
                                                      dport)
                        self.packetlist.append(packet)
                    else:
                        self.packetid += 1
                        packet = self._create_summary(self.packetid,
                                                      self._get_timestamp(pkt),
                                                      ip_src,
                                                      ip_dst,
                                                      "UDPv6",
                                                      len(pkt),
                                                      pkt.summary(),
                                                      sport,
                                                      dport)
                        self.packetlist.append(packet)
                    if not isinstance(writer, str):
                        writer.write(pkt)

                # ICMP报文
                elif ip_payload.name == "IPv6 Extension Header - Hop-by-Hop Options Header":
                    self.packetid += 1
                    packet = self._create_summary(self.packetid,
                                                  self._get_timestamp(pkt),
                                                  ip_src,
                                                  ip_dst,
                                                  "ICMPv6",
                                                  len(pkt),
                                                  pkt.summary(),
                                                  -1,
                                                  -1)
                    self.packetlist.append(packet)
                    if not isinstance(writer, str):
                        writer.write(pkt)
            # ARP报文
            elif pkt.payload.name == "ARP":
                self.counter["ARP"] += 1
                self.packetid += 1
                packet = self._create_summary(self.packetid,
                                              self._get_timestamp(pkt),
                                              mac_src,
                                              mac_dst,
                                              "ARP",
                                              len(pkt),
                                              pkt.summary(),
                                              -1,
                                              -1)
                self.packetlist.append(packet)
                if not isinstance(writer, str):
                    writer.write(pkt)
            # 不属于以上三种协议
            else:
                return
        # 不属于以太帧
        else:
            return

    def _get_timestamp(self, pkt):
        if self.packetid == 1:
            self.starttime = pkt.time
            return round(0, 6)
        else:
            return round(pkt.time-self.starttime, 6)

    def _create_summary(self, no, timestamp, src, dst, proto, length, info, sport, dport):
        res = dict()
        res["No"] = no
        res["Time"] = timestamp
        res["Src"] = src
        res["Dst"] = dst
        res["Proto"] = proto
        res["Len"] = length
        res["Info"] = info
        res["Sport"] = sport
        res["Dport"] = dport
        return res.copy()

    def _format_time(self, timestamp):
        delta_ms = str(timestamp - int(timestamp))
        time_temp = time.localtime(timestamp)
        my_time = time.strftime("%Y-%m-%d %H:%M:%S", time_temp)
        my_time += delta_ms[1:8]
        return my_time

    def start(self):
        """
        开始捕获数据包
        :param trigger: Threading.Event() 更新触发器
        :return: None
        """
        if self.startflag:
            return
        elif self.stopflag:
            self.stopflag = False
            self.startflag = True
            self.loadflag = False
            # 清空临时变量
            self._clean()
            # daemon=True保证主进程退出时子进程一并退出
            capture = threading.Thread(target=self._capture, daemon=True)
            capture.start()
        elif self.pauseflag:
            self.pauseflag = False
            self.startflag = True
            self.loadflag = False
        # self._capture()

    def stop(self):
        """
        停止捕获数据包
        :return: None
        """
        self.startflag = False
        self.pauseflag = False
        self.stopflag = True

    def pause(self):
        """
        暂停捕获数据包
        :return: None
        """
        if self.stopflag or self.pauseflag:
            return
        else:
            self.startflag = False
            self.pauseflag = True

    def save_pcap(self, filename, filter=None):
        """
        将捕捉到的数据包保存为文件
        upadte 1: 增加可选参数filter
        :param filename: 文件名
        :param filter: 过滤出来的包id列表
        :return: True if Success else False
        """
        if filename.find(".pcap") == -1:
            filename += ".pcap"
        try:
            if isinstance(filter, list):
                last_id = 0
                try:
                    writer = PcapWriter(filename, append=True, sync=True)
                    for name in self.temp_list:
                        reader = PcapReader(name)
                        for id in filter:
                            if not isinstance(id, int):
                                id = int(id)
                            for i in range(id - last_id):
                                packet = reader.next()
                            writer.write(packet)
                            last_id = id
                        reader.close()
                except Exception as e:
                    raise Exception
                else:
                    # reader.close()
                    writer.close()
            else:
                writer = PcapWriter(filename, append=True, sync=True)
                for i in range(len(self.temp_list)):
                    if (i+1)*1000 < self.packetid:
                        reader = PcapReader(self.temp_list[i])
                        for n in range(1000):
                            packet = reader.next()
                            writer.write(packet)
                    else:
                        reader = PcapReader(self.temp_list[i])
                        for n in range(self.packetid % 1000):
                            packet = reader.next()
                            writer.write(packet)
                    reader.close()
                writer.close()
                '''
                writer = open(filename, "w+b")
                for name in self.temp_list:
                    reader = open(name, "rb")
                    writer.write(reader.read())
                    reader.close()
                writer.close()
                '''
                # shutil.copy(self.tempname, filename)
                # os.chmod(filename, 0o0400 | 0o0200 | 0o0040 | 0o0004)
        except Exception as e:
            # raise Exception
            return False
        else:
            return True

    def load_pcap(self, filename):
        """
        加载数据文件到内存中
        :param filename: 文件名
        :return: True if Success else False
        """
        try:
            self._clean()
            self.tempname = filename
            self.temp_list.append(self.tempname)
            reader = PcapReader(filename)
            for packet in reader:
                self._analyze_packet(packet, "save")
        except Exception as e:
            print(e)
            return False
        else:
            self.loadflag = True
            return True

    def get_packet_by_id(self, id):
        """
        通过序号获取数据包
        :param id: 数据包序号
        :return: scapy.packet.Packet, 如果获取失败，返回str："Error"
        """
        try:
            # 防止id不为integer
            if not isinstance(id, int):
                id = int(id)
            if id > self.packetid:
                return "Error"

            # 判断当前是否为加载的pcap
            if not self.loadflag:
                # 根据id获取缓存，提高IO速度
                buffer_id = int((id-1)/1000)
                reader = PcapReader(self.temp_list[buffer_id])
                for i in range((id-1) % 1000 + 1):
                    packet = reader.next()
                return packet
            else:
                reader = PcapReader(self.tempname)
                for i in range(id):
                    packet = reader.next()
                return packet
        except:
            return "Error"
        finally:
            reader.close()

    def get_detailed_packet(self, pkt, layer, id):
        """
        获取数据包分层信息
        :param pkt: scapy.packet.Packet, 数据包
        :param layer: 用于接收分层信息的list
        :param id: 包序号
        :return: 对外：None， 对递归：下一层信息的list
        """
        # 最后一层
        protocol = pkt.name
        if protocol == "NoPayload":
            return []

        # Frame + Ethernet II
        if protocol == "Ethernet":
            frame_descript = "frame {0}: {1} bytes on wire ({2} bits), {3} bytes captured ({4} bits) on {5}".format(
                id, pkt.wirelen, pkt.wirelen << 3, len(pkt), len(pkt) << 3, self.iface
            )
            layer.append(frame_descript)
            ftype = "Encapsulation type: {}".format(pkt.name)
            artime = "Arrival Time: {} 中国标准时间".format(self._format_time(pkt.time))
            eptime = "Epoch Time: {} seconds".format(pkt.time)
            # timeoffirst = "[Time since reference or first frame: {} seconds]".format(self._get_timestamp(pkt))
            fnum = "Frame Number: {}".format(id)
            flen = "Frame Length: {} bytes ({} bits)".format(pkt.wirelen, pkt.wirelen << 3)
            clen = "Capture Length: {} bytes ({} bits)".format(len(pkt), len(pkt) << 3)
            proto = "Protocols in frame: {}".format(self.packetlist[id-1]["Proto"])
            layer.append(ftype)
            layer.append(artime)
            layer.append(eptime)
            # layer.append(timeoffirst)
            layer.append(fnum)
            layer.append(flen)
            layer.append(clen)
            layer.append(proto)
            # Ethernet II
            ether_descript = "Ethernet II, Src: {}, Dst: {}".format(pkt.src, pkt.dst)
            ether = list()
            ether.append(ether_descript)
            layer.append(ether)
            mac_dst = "Destination: {}".format(pkt.dst)
            mac_src = "Source: {}".format(pkt.src)
            # pkt = pkt.payload

            # Type
            if pkt.payload.name == "IP":
                etype = "Type: IPv4 (0x0800)"
            elif pkt.payload.name == "IPv6":
                etype = "Type: IPv6 (0x86DD)"
            else:
                etype = "Type: ARP (0x0806)"

            ether.append(mac_dst)
            ether.append(mac_src)
            ether.append(etype)

            pkt = pkt.payload
            ether.append(self.get_detailed_packet(pkt, list(), id))
            return layer

        # IPv4
        elif protocol == "IP":
            ip_descript = "Internet Protocol Version 4, Src: {}, Dst: {}".format(
                pkt.src, pkt.dst
            )
            layer.append(ip_descript)
            version = "Version: 4"
            layer.append(version)
            hlen = "Header Length: {} bytes ({})".format(pkt.ihl << 2, pkt.ihl)
            layer.append(hlen)
            dsf = "Differentiated Services Field: {}".format(hex(pkt.tos))
            layer.append(dsf)
            tlen = "Total Length: {}".format(pkt.len)
            layer.append(tlen)
            ident = "Identification: {} ({})".format(hex(pkt.id), pkt.id)
            layer.append(ident)

            # flags
            flags = list()
            flags.append("Flags: {}".format(hex(pkt.flags.value)))
            reserve = "{}... .... .... .... = Reserved bit: {}".format(
                pkt.flags.value >> 15,
                "Set" if (pkt.flags.value >> 15) else "Not set"
            )
            frag = ".{}.. .... .... .... = Don't fragment: {}".format(
                (pkt.flags.value >> 14) % 2,
                "Set" if ((pkt.flags.value >> 14) % 2) else "Not set"
            )
            more = "..{}. .... .... .... = More fragments: {}".format(
                (pkt.flags.value >> 13) % 2,
                "Set" if ((pkt.flags.value >> 14) % 2) else "Not set"
            )
            offset = "...{} {:04b} {:04b} {:04b} = Fragment offset: {}".format(
                (pkt.flags.value >> 12) % 2,
                (pkt.flags.value >> 8) % 16,
                (pkt.flags.value >> 4) % 16,
                pkt.flags.value % 16,
                pkt.flags.value % 8192,
            )
            flags.append(reserve)
            flags.append(frag)
            flags.append(more)
            flags.append(offset)
            layer.append(flags)

            ttl = "Time to live: {}".format(pkt.ttl)
            layer.append(ttl)
            pro = "Protocol: {} ({})".format(pkt.payload.name, pkt.proto)
            layer.append(pro)
            ip_chksum = "Header checksum: {}".format(hex(pkt.chksum))
            layer.append(ip_chksum)
            ip_chk = "[Header checksum status: Unverified]"
            layer.append(ip_chk)
            ip_src = "Source: {}".format(pkt.src)
            layer.append(ip_src)
            ip_dst = "Destination: {}".format(pkt.dst)
            layer.append(ip_dst)

        # IPv6
        elif protocol == "IPv6":
            ipv6_descript = "Internet Protocol Version 6, Src: {}, Dst: {}".format(
                pkt.src, pkt.dst
            )
            layer.append(ipv6_descript)
            version = "Version: 6"
            layer.append(version)
            plen = "Payload Length: {}".format(pkt.plen)
            layer.append(plen)
            nheader = "Next Header: {} ({})".format(
                "ICMPv6" if pkt.payload.name == "IPv6 Extension Header - Hop-by-Hop Options Header"
                else pkt.payload.name,
                pkt.nh)
            layer.append(nheader)
            hl = "Hop Limit: {}".format(pkt.hlim)
            layer.append(hl)
            ipv6_src = "Source: {}".format(pkt.src)
            layer.append(ipv6_src)
            ipv6_dst = "Destination: {}".format(pkt.dst)
            layer.append(ipv6_dst)

        # ARP
        elif protocol == "ARP":
            arp_descript = "Address Resolution Protocol"
            layer.append(arp_descript)
            ht = "Hardware type: Ethernet ({})".format(pkt.hwtype)
            layer.append(ht)
            pro = "Protocol Type: {} ({})".format(
                "IPv4" if pkt.ptype == 2048 else "IPv6",
                "0x0800" if pkt.ptype == 2048 else hex(pkt.ptype)
            )
            layer.append(pro)
            hs = "Hardware Size: {}".format(pkt.hwlen)
            layer.append(hs)
            ps = "Protocol Size: {}".format(pkt.plen)
            layer.append(ps)
            op = "Opcode: {}".format(pkt.op)
            layer.append(op)
            smac_ad = "Sender MAC address: {}".format(pkt.hwsrc)
            layer.append(smac_ad)
            sip_ad = "Sender IP address: {}".format(pkt.psrc)
            layer.append(sip_ad)
            tmac_ad = "Target MAC address: {}".format(pkt.hwdst)
            layer.append(tmac_ad)
            tip_ad = "Target IP address: {}".format(pkt.pdst)
            layer.append(tip_ad)

        # TCP
        elif protocol == "TCP":
            tcp_descript = "Transmission Control Protocol, Src Port: {}, Dst Port: {}, Seq: {}, Ack: {}, Len: {}".format(
                pkt.sport, pkt.dport, pkt.seq, pkt.ack, len(pkt.payload)
            )
            layer.append(tcp_descript)
            tcp_sport = "Source Port: {}".format(pkt.sport)
            layer.append(tcp_sport)
            tcp_dport = "Destination Port: {}".format(pkt.dport)
            layer.append(tcp_dport)
            ts = "[TCP Segment Len: {}]".format(len(pkt.payload))
            layer.append(ts)
            seq = "Sequence number: {}".format(pkt.seq)
            layer.append(seq)
            ack = "Acknowledgment number: {}".format(pkt.ack)
            layer.append(ack)
            hdlen = "{:04b} .... = Header Length: {} bytes ({})".format(
                pkt.dataofs, pkt.dataofs << 2, pkt.dataofs
            )
            layer.append(hdlen)

            # Flags
            flags = list()
            flags.append("Flags: {}".format(hex(pkt.flags.value)))
            reserved = "{:03b}. .... .... = Reserved: {}".format(
                pkt.flags.value >> 9,
                "Set" if (pkt.flags.value >> 9) else "Not set"
            )
            flags.append(reserved)
            nonce = "...{} .... .... = Nonce: {}".format(
                (pkt.flags.value >> 8) % 2,
                "Set" if ((pkt.flags.value >> 8) % 2) else "Not set"
            )
            flags.append(nonce)
            cwr = ".... {}... .... = Congestion Window Reduced (CWR): {}".format(
                (pkt.flags.value >> 7) % 2,
                "Set" if ((pkt.flags.value >> 7) % 2) else "Not set"
            )
            flags.append(cwr)
            echo = ".... .{}.. .... = ECN-Echo: {}".format(
                (pkt.flags.value >> 6) % 2,
                "Set" if (pkt.flags.value >> 6 % 2) else "Not set"
            )
            flags.append(echo)
            urg = ".... ..{}. .... = Urgent: {}".format(
                (pkt.flags.value >> 5) % 2,
                "Set" if (pkt.flags.value >> 5 % 2) else "Not set"
            )
            flags.append(urg)
            ackn = ".... ...{} .... = Acknowledgment: {}".format(
                (pkt.flags.value >> 4) % 2,
                "Set" if (pkt.flags.value >> 4 % 2) else "Not set"
            )
            flags.append(ackn)
            push = ".... .... {}... = Push: {}".format(
                (pkt.flags.value >> 3) % 2,
                "Set" if (pkt.flags.value >> 3 % 2) else "Not set"
            )
            flags.append(push)
            rst = ".... .... .{}.. = Reset: {}".format(
                (pkt.flags.value >> 2) % 2,
                "Set" if (pkt.flags.value >> 2 % 2) else "Not set"
            )
            flags.append(rst)
            syn = ".... .... ..{}. = Syn: {}".format(
                (pkt.flags.value >> 1) % 2,
                "Set" if (pkt.flags.value >> 1 % 2) else "Not set"
            )
            flags.append(syn)
            fin = ".... .... ...{} = Fin: {}".format(
                pkt.flags.value % 2,
                "Set" if pkt.flags.value % 2 else "Not set"
            )
            flags.append(fin)
            layer.append(flags)

            wsize = "Window size value: {}".format(pkt.window)
            layer.append(wsize)
            tcp_chksum = "Checksum: {}".format(hex(pkt.chksum))
            layer.append(tcp_chksum)
            layer.append("[Checksum status: Unverified]")
            urgpt = "Urgent pointer: {}".format(pkt.urgptr)
            layer.append(urgpt)
            tcp_payload = "TCP payload ({} bytes)".format(len(pkt.payload))
            layer.append(tcp_payload)

        # UDP
        elif protocol == "UDP":
            udp_descript = "User Datagram Protocol, Src Port: {}, Dst Port: {}".format(
                pkt.sport, pkt.dport
            )
            layer.append(udp_descript)
            udp_sport = "Source Port: {}".format(pkt.sport)
            layer.append(udp_sport)
            udp_dport = "Destination Port: {}".format(pkt.dport)
            layer.append(udp_dport)
            udp_len = "Length: {}".format(pkt.len)
            layer.append(udp_len)
            udp_chksum = "Checksum: {}".format(hex(pkt.chksum))
            layer.append(udp_chksum)
            layer.append("[Checksum status: Unverified]")
            udp_data = "Data ({} bytes)".format(len(pkt.payload))
            layer.append(udp_data)

        # ICMP
        elif protocol == "ICMP":
            icmp_descript = "Internet Control Message Protocol"
            layer.append(icmp_descript)
            if pkt.type == 8:
                icmp_type = "Type: 8 (Echo (ping) request)"
            elif pkt.type == 0:
                icmp_type = "Type: 0 (Echo (ping) reply)"
            else:
                icmp_type = "Type: {} (Error)".format(pkt.type)
            layer.append(icmp_type)
            icmp_code = "Code: {}".format(pkt.code)
            layer.append(icmp_code)
            icmp_chk = pkt.__class__(raw(pkt[pkt.__class__])).chksum
            icmp_chksum = "Checksum: {} [{}]".format(hex(pkt.chksum),
                                                     "correct" if icmp_chk==pkt.chksum else "incorrect")
            layer.append(icmp_chksum)
            icmp_status = "[Checksum Status: {}]".format("Good" if icmp_chk==pkt.chksum else "Bad")
            layer.append(icmp_status)
            icmp_id = "Identifier (BE): {} ({})".format(pkt.id, hex(pkt.id))
            layer.append(icmp_id)
            icmp_seq = "Sequence number (BE): {} ({})".format(pkt.seq, hex(pkt.seq))
            layer.append(icmp_seq)
            icmp_data = "Data ({} bytes)".format(len(pkt.payload))
            layer.append(icmp_data)

        else:
            return []

        pkt = pkt.payload
        layer.append(self.get_detailed_packet(pkt, list(), id))
        return layer

    def get_hexdump(self, pkt):
        """
        获取报文的16进制格式化字符串（类似WireShark最下方窗口）
        :param pkt: scapy.packet.Packet, 抓取到的报文
        :return: str, 16进制格式化字符串
        """
        return hexdump(pkt, dump=True)
