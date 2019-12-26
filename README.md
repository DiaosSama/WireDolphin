# WireDolphin
 A simple packet analyzer which is created for course design of computer network.

Author：DiaosSama、LoserSheep、Wearless

## 运行环境

Python3.6.x及以上

Windows10（Linux不保证兼容）

## 安装说明

安装所需库：`pip install -r requirement.txt`

## 运行说明

`python main.py`

也可以从release处直接下载打包好的可执行文件运行，适用于Windows x64

## 功能介绍

- 可以分析处理以下协议包：IPv4/6, TCP, UDP, HTTP(S), DNS, MDNS, SSDP, ICMP

  （HTTPS协议分析存在逻辑问题，尚未修复）

- 提供报文分层信息以及原始数据流信息

- 提供报文实时统计功能

- 支持pcap文件存储及读取

- 具备过滤器功能，过滤器使用说明详见 `/doc/filter instruction.md`

