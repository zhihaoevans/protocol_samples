# 网络协议分类整理（概览与速查）

本文件按“OSI 分层 + 使用场景”两条主线进行分类，覆盖目前公开、常用的网络协议与技术栈。由于协议生态非常庞大、且持续演进，本文旨在提供清晰的导航与速查，并不保证穷尽所有边缘或专有协议。欢迎在后续迭代中补充完善。

## 分类方法
- 分层视角：物理/链路层 → 网络层 → 传输层 → 会话/表示/应用层。
- 用途视角：路由与控制、名称与地址、认证与安全、管理与监控、文件/媒体/消息/IoT/工业等细分场景。

---

## 物理与链路层（L1/L2）
- 以太网（IEEE 802.3）：局域网有线基础；含以太帧结构与速率族（10M/100M/1G/10G/…）。
- Wi‑Fi（IEEE 802.11 a/b/g/n/ac/ax/be）：无线局域网标准族。
- 蓝牙（Bluetooth BR/EDR、BLE）：短距无线；常用于外设与低功耗通信。
- Zigbee / Thread（IEEE 802.15.4）：低速率、低功耗物联网无线协议。
- NFC：近场通信，超短距离数据交换。
- LoRaWAN：长距离、低功耗 LPWAN；物联网广域连接。
- 蜂窝网络（2G/3G/4G/LTE/5G）：移动宽带及核心网承载（GTP 等在上层）。
- PPP / HDLC：串行链路封装与点对点链路控制。
- DOCSIS：有线电视网数据业务标准。
- Frame Relay / ATM：历史性广域网承载技术。
- 802.1X / EAP：链路接入控制与认证框架。
- 以太网 OAM（802.1ag / Y.1731）：以太运维与故障管理。
- STP/RSTP/MSTP（生成树）：二层环路避免与拓扑收敛。
- LACP（802.1AX）：链路聚合控制。

## 网络层与隧道（L3/Overlay）
- IPv4 / IPv6：主流网络层协议；含地址、分片、路由等。
- ARP / NDP：地址解析（IPv4/IPv6）。
- ICMPv4/v6：控制消息与诊断（例如 Ping）。
- IGMP / MLD：组播成员管理（IPv4/IPv6）。
- MPLS：多协议标签交换；面向转发与流量工程。
- GRE / IP‑in‑IP：通用隧道与 IP 封装。
- L2TP / PPTP：二层隧道与早期 VPN 技术。
- VXLAN / NVGRE / Geneve：数据中心网络 Overlay 封装。
- SR‑MPLS / SRv6：基于段路由的路径控制。
- GTP：移动核心网隧道（GPRS/4G/5G）。
- LISP / OTV：地址/位置分离与数据中心扩展技术。

## 传输层（L4）
- TCP：面向连接、可靠传输；拥塞控制与流量管理。
- UDP：无连接、低开销；适用于实时与简单请求/响应。
- SCTP：多宿主、多流特性；信令与专用场景。
- DCCP：面向拥塞控制的无连接传输。
- QUIC：基于 UDP 的传输＋加密；集成拥塞控制与 0‑RTT。

## 路由与控制（动态路由/冗余/组播）
- BGP：域间路由协议；含 EVPN 等扩展用于二层/三层 Overlay。
- OSPFv2/v3 / IS‑IS：链路状态路由（域内）；v3 支持 IPv6。
- RIP（含ng）：距离向量路由；历史与小规模网络。
- EIGRP：思科增强型距离向量（专有为主）。
- PIM‑SM/DM：组播路由（稀疏/密集模式）。
- HSRP / VRRP / GLBP：网关冗余协议。
- TRILL / SPB：二层多路径与路由桥接。
- LLDP：链路层邻居发现。

## 地址与名称服务
- DHCPv4/v6：动态地址分配与参数下发。
- DNS / mDNS / DNS‑SD：域名系统、局域网多播解析与服务发现。
- NAT‑PMP / PCP：NAT 端口映射控制。
- UPnP / SSDP：即插即用与简单服务发现。

## 安全与认证
- TLS 1.2/1.3 / DTLS：传输层加密（TCP/UDP）；网站与 API 安全基础。
- IPsec（IKEv1/v2, ESP/AH）：网络层加密与隧道；站点到站点/远程接入。
- SSH：安全远程登录与隧道转发。
- Kerberos：基于票据的认证体系（多用于企业域）。
- RADIUS / Diameter：AAA（认证、授权、计费）。
- 802.1X / EAP 家族：接入认证（EAP‑TLS/PEAP 等）。
- WPA2/WPA3：Wi‑Fi 安全。
- S/MIME / OpenPGP：邮件端到端安全。
- SPF / DKIM / DMARC：邮件域名防伪与可信度策略。
- SAML / OAuth 2.0 / OpenID Connect：联邦身份与授权（基于 HTTP）。

## 管理、监控与可观测性
- SNMP：网络管理与 MIB；设备监控与告警。
- NETCONF / gNMI：现代化网络设备配置与状态读取。
- Syslog：系统/网络设备日志收集。
- IPFIX / NetFlow / sFlow：流量导出与分析。
- TR‑069 / CWMP：宽带设备远程管理。

## 时间同步
- NTP：网络时间同步；互联网/局域网常用。
- PTP（IEEE 1588）：高精度时间同步；工业/金融等低抖动场景。

## Web 与 API
- HTTP/1.1 / HTTP/2 / HTTP/3（QUIC）：万维网与现代 API 基础。
- WebSocket：双向实时通信（基于 HTTP 升级）。
- gRPC：基于 HTTP/2 的高性能 RPC 框架与协议。
- SOAP：基于 XML 的消息协议（历史/企业集成）。
- WebDAV：基于 HTTP 的文件协作。

## 邮件
- SMTP / Submission / LMTP：邮件传输与提交。
- POP3 / IMAP：邮件收取与同步。

## 文件与存储
- FTP / FTPS / SFTP / TFTP：文件传输（安全/非安全/简单）。
- NFS：网络文件系统（类 Unix）。
- SMB/CIFS / AFP：文件共享（Windows/macOS）。
- iSCSI / NVMe‑oF / NBD：块存储联网协议。

## 实时媒体与通信
- RTP/RTCP / SRTP：实时媒体传输与控制（含加密）。
- SIP / SDP / H.323：会话建立与多媒体控制。
- RTSP / RTMP：流媒体控制与分发（历史与当前并存）。
- WebRTC：浏览器实时通信（ICE/STUN/TURN, DTLS‑SRTP 等）。
- HLS / MPEG‑DASH：HTTP 自适应流媒体分发。

## 消息与队列
- MQTT / MQTT‑SN：轻量发布/订阅，物联网常用。
- AMQP：高级消息队列协议（企业集成）。
- STOMP：文本帧消息传输。
- DDS：数据分发服务，实时系统与工业场景。
- Kafka 协议：分布式流处理平台的有线协议。
- ZeroMQ（ZMQ）/ Nanomsg：消息库的线路协议族。

## 远程访问与桌面
- Telnet：早期明文远程登录（不安全）。
- SSH：安全远程登录与命令执行。
- RDP：远程桌面协议（Windows）。
- VNC：跨平台远程桌面共享。
- X11：图形显示协议（网络透明）。

## 目录与身份
- LDAP / LDAPS：目录访问与管理；企业用户/资源目录。
- Active Directory：基于 LDAP/Kerberos 的目录与身份服务。

## 物联网与资源受限网络
- CoAP：轻量 RESTful 协议（基于 UDP）。
- Zigbee / Z‑Wave / Thread：家庭与楼宇自动化无线协议族。
- NB‑IoT / LoRaWAN：窄带蜂窝/LPWAN。
- MQTT / MQTT‑SN：低功耗发布/订阅通信。

## 工业控制与电力
- Modbus/TCP：工业现场常用；简单寄存器/线圈读写。
- DNP3：电力系统与 SCADA。
- IEC 60870‑5‑104：远动与电力控制。
- IEC 61850（MMS/GOOSE/SV）：变电站通信与实时信号。
- PROFINET / Profibus / EtherCAT：工业以太与现场总线。
- OPC UA：工业互联与语义建模。
- BACnet：楼宇自动化。

## P2P 与分布式网络
- BitTorrent：分布式文件分发与 DHT（Kademlia）。
- Gnutella：早期 P2P 网络。
- libp2p：模块化 P2P 协议栈（多用于区块链/分布式应用）。
- Tor（洋葱路由）：匿名通信网络。

## 云与数据中心网络
- EVPN（BGP 扩展）：二层/三层虚拟网络与多租户。
- VXLAN / NVGRE / Geneve：数据中心 Overlay。
- TRILL / SPB：二层多路径。
- LISP：位置/标识分离，灵活寻址。

## 打印与周边
- IPP / IPPS：互联网打印协议（安全/非安全）。
- LPD：行式打印机守护进程协议。
 - AirPrint：苹果生态打印。参阅：[Apple AirPrint](https://support.apple.com/zh-cn/HT201311)

## 其他与历史协议
- X.25 / SLIP / UUCP：早期网络与串行通信协议。
- Gopher / Finger：早期互联网应用层协议。

---

## 维护与扩展说明
- 本清单强调“公开、常用”的协议族，兼顾历史与现状；不包含专有或不可公开规范的私有协议。
- 若需更细的专业分类（例如移动核心网、广播电视、卫星链路等），建议在对应子领域建立独立章节或文档。
- 欢迎补充：新增协议、修正描述、添加参考标准（RFC/IEEE/3GPP/IEC 等）。

---

## 速查表（端口、协议号与标准参考）

说明：端口与协议号为“常见/默认”配置；具体部署可变。RFC/标准编号为主参考，部分协议为行业/厂商规范。

### 网络与传输基础
- IPv4：[RFC 791](https://www.rfc-editor.org/rfc/rfc791)
- IPv6：[RFC 8200](https://www.rfc-editor.org/rfc/rfc8200)
- ARP：[RFC 826](https://www.rfc-editor.org/rfc/rfc826)
- NDP（IPv6 邻居发现）：[RFC 4861](https://www.rfc-editor.org/rfc/rfc4861)
- ICMPv4：[RFC 792](https://www.rfc-editor.org/rfc/rfc792)；ICMPv6：[RFC 4443](https://www.rfc-editor.org/rfc/rfc4443)
- TCP：[RFC 9293](https://www.rfc-editor.org/rfc/rfc9293)（更新汇编）；UDP：[RFC 768](https://www.rfc-editor.org/rfc/rfc768)
- QUIC：传输 [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)，TLS 集成 [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001)，恢复 [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002)
 - 实用参考： [Wireshark](https://www.wireshark.org/)、[tcpdump](https://www.tcpdump.org/)、[Scapy](https://scapy.net/)

### 路由与控制
- BGP：`TCP/179`，[RFC 4271](https://www.rfc-editor.org/rfc/rfc4271)
- OSPFv2：IP 协议号 `89`，[RFC 2328](https://www.rfc-editor.org/rfc/rfc2328)；OSPFv3：[RFC 5340](https://www.rfc-editor.org/rfc/rfc5340)
- IS‑IS：CLNS（无端口），`ISO/IEC 10589`
- RIP v2：`UDP/520`，[RFC 2453](https://www.rfc-editor.org/rfc/rfc2453)
- PIM‑SM：IP 协议号 `103`，[RFC 7761](https://www.rfc-editor.org/rfc/rfc7761)
- VRRP：IP 协议号 `112`，[RFC 5798](https://www.rfc-editor.org/rfc/rfc5798)
- HSRP：`UDP/1985`（思科规范）
- LLDP：以太网类型 `0x88CC`，`IEEE 802.1AB`
 - 实用参考： [FRRouting](https://frrouting.org/)、[BIRD](https://bird.network.cz/)、[OpenBGPD](https://www.openbgpd.org/)

### 隧道与 Overlay
- GRE：IP 协议号 `47`，[RFC 2784](https://www.rfc-editor.org/rfc/rfc2784)
- L2TP：`UDP/1701`，[RFC 2661](https://www.rfc-editor.org/rfc/rfc2661)
- PPTP：`TCP/1723`（控制），`GRE/47`（隧道）
- IPsec：ESP `IP/50`，AH `IP/51`；IKEv2 `UDP/500`，NAT‑T `UDP/4500`；[RFC 4303](https://www.rfc-editor.org/rfc/rfc4303)/[RFC 4302](https://www.rfc-editor.org/rfc/rfc4302)/[RFC 7296](https://www.rfc-editor.org/rfc/rfc7296)
- VXLAN：`UDP/4789`，[RFC 7348](https://www.rfc-editor.org/rfc/rfc7348)
- Geneve：`UDP/6081`，[RFC 8926](https://www.rfc-editor.org/rfc/rfc8926)
- MPLS：[RFC 3031](https://www.rfc-editor.org/rfc/rfc3031)（无端口，标签交换）
 - 实用参考： [strongSwan](https://www.strongswan.org/)、[OpenVPN](https://openvpn.net/)、[WireGuard](https://www.wireguard.com/)、[iproute2](https://wiki.linuxfoundation.org/networking/iproute2)

### 名称与地址
- DNS：`UDP/TCP/53`，[RFC 1034](https://www.rfc-editor.org/rfc/rfc1034)/[RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)
- mDNS / DNS‑SD：`UDP/5353`，[RFC 6762](https://www.rfc-editor.org/rfc/rfc6762)/[RFC 6763](https://www.rfc-editor.org/rfc/rfc6763)
- DHCPv4：服务器 `UDP/67`，客户端 `UDP/68`，[RFC 2131](https://www.rfc-editor.org/rfc/rfc2131)/[RFC 2132](https://www.rfc-editor.org/rfc/rfc2132)
- DHCPv6：`UDP/546`（客户端），`UDP/547`（服务器），[RFC 8415](https://www.rfc-editor.org/rfc/rfc8415)
- NAT‑PMP：`UDP/5351`（Apple 规范）；PCP：`UDP/5351`，[RFC 6887](https://www.rfc-editor.org/rfc/rfc6887)
- UPnP/SSDP：`UDP/1900`（多播）
 - 实用参考： [BIND](https://www.isc.org/bind/)、[PowerDNS](https://www.powerdns.com/)、[Knot DNS](https://www.knot-dns.cz/)、[ISC Kea DHCP](https://www.isc.org/kea/)、[dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html)

### 安全与认证
- TLS 1.3：[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)；DTLS：[RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)
- SSH：`TCP/22`，[RFC 4253](https://www.rfc-editor.org/rfc/rfc4253) 及同族
- Kerberos：`UDP/TCP/88`，[RFC 4120](https://www.rfc-editor.org/rfc/rfc4120)
- RADIUS：`UDP/1812`（认证），`UDP/1813`（记账）；老端口 `1645/1646`
- Diameter：`TCP/SCTP/3868`，[RFC 6733](https://www.rfc-editor.org/rfc/rfc6733)
- WPA2/WPA3：`IEEE 802.11i/802.11‑2016/802.11ax`
- S/MIME：[RFC 8551](https://www.rfc-editor.org/rfc/rfc8551)；OpenPGP：[RFC 4880](https://www.rfc-editor.org/rfc/rfc4880)
- SPF：[RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)；DKIM：[RFC 6376](https://www.rfc-editor.org/rfc/rfc6376)；DMARC：[RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)
 - 实用参考： [OpenSSL](https://www.openssl.org/)、[LibreSSL](https://www.libressl.org/)、[GnuTLS](https://www.gnutls.org/)、[OpenSSH](https://www.openssh.com/)、[FreeRADIUS](https://freeradius.org/)

### 管理与监控
- SNMP：`UDP/161`（查询），`UDP/162`（Trap），[RFC 1157](https://www.rfc-editor.org/rfc/rfc1157)/[RFC 3411](https://www.rfc-editor.org/rfc/rfc3411)+
- NETCONF：`SSH/TCP/830`；`TLS/TCP/6513`，[RFC 6241](https://www.rfc-editor.org/rfc/rfc6241)
- gNMI：常用 `TCP/9339`（基于 gRPC/HTTP2，规范由 OpenConfig）
- Syslog：`UDP/514`（常见），`TCP/514`/`TLS/6514`，[RFC 5424](https://www.rfc-editor.org/rfc/rfc5424)/[RFC 5425](https://www.rfc-editor.org/rfc/rfc5425)
- NetFlow v5：`UDP/2055`（常见端口）；IPFIX：`UDP/TCP/SCTP/4739`，[RFC 7011](https://www.rfc-editor.org/rfc/rfc7011)
- sFlow：`UDP/6343`
- TR‑069（CWMP）：`HTTP/HTTPS`，`DSL Forum` 规范
 - 实用参考： [Net-SNMP](http://www.net-snmp.org/)、[gNMIc](https://gnmic.openconfig.net/)、[rsyslog](https://www.rsyslog.com/)、[syslog-ng](https://www.syslog-ng.com/)、[pmacct](http://www.pmacct.net/)

### 时间同步
- NTP：`UDP/123`，[RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)
- PTP：`IEEE 1588`（端口依实现，常见为以太网组播）
 - 实用参考： [chrony](https://chrony-project.org/)、[NTPd](https://www.ntp.org/)、[linuxptp (ptp4l/phc2sys)](https://github.com/richardcochran/linuxptp)

### Web 与 API
- HTTP/1.1：`TCP/80`（默认），[RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)
- HTTPS（TLS）：`TCP/443`（默认），[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
- HTTP/2：复用 `TCP/443`（ALPN `h2`），[RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)
- HTTP/3（QUIC）：`UDP/443`（ALPN `h3`），[RFC 9114](https://www.rfc-editor.org/rfc/rfc9114)
- WebSocket：`ws://`（80）、`wss://`（443），[RFC 6455](https://www.rfc-editor.org/rfc/rfc6455)
- gRPC：基于 `HTTP/2`（常见 443/自定义端口），规范由 CNCF/Google
- SOAP：`HTTP` 传输为主（端口随服务），`W3C` 规范
- WebDAV：`HTTP/HTTPS`，[RFC 4918](https://www.rfc-editor.org/rfc/rfc4918)
 - 实用参考： [Nginx](https://nginx.org/)、[Apache HTTP Server](https://httpd.apache.org/)、[Envoy](https://www.envoyproxy.io/)、[grpcurl](https://github.com/fullstorydev/grpcurl)

### 邮件
- SMTP：`TCP/25`；提交 `TCP/587`；加密提交 `TCP/465`（SMTPS），[RFC 5321](https://www.rfc-editor.org/rfc/rfc5321)
- IMAP：`TCP/143`；IMAPS：`TCP/993`，[RFC 3501](https://www.rfc-editor.org/rfc/rfc3501)
- POP3：`TCP/110`；POP3S：`TCP/995`，[RFC 1939](https://www.rfc-editor.org/rfc/rfc1939)
 - 实用参考： [Postfix](https://www.postfix.org/)、[Exim](https://www.exim.org/)、[Dovecot](https://www.dovecot.org/)

### 文件与存储
- FTP：`TCP/21`（控制）＋数据端口（主动 `TCP/20`/被动动态），[RFC 959](https://www.rfc-editor.org/rfc/rfc959)
- FTPS：`TCP/21`＋TLS（或隐式 `TCP/990`）
- SFTP：走 `SSH/TCP/22`（与 FTP 不同协议）
- TFTP：`UDP/69`，[RFC 1350](https://www.rfc-editor.org/rfc/rfc1350)
- NFS：端口由 `rpcbind`/`mountd`/`nfsd` 协商，[RFC 7530](https://www.rfc-editor.org/rfc/rfc7530)
- SMB/CIFS：`TCP/445`（现代）；`TCP/137-139`（NetBIOS），`MS‑SMB` 规范
- iSCSI：`TCP/3260`，[RFC 3720](https://www.rfc-editor.org/rfc/rfc3720)
- NVMe‑oF：`RDMA`/`TCP`/`Fibre Channel`，`NVM Express` 规范
 - 实用参考： [vsftpd](https://security.appspot.com/vsftpd.html)、[ProFTPD](http://www.proftpd.org/)、[Samba](https://www.samba.org/)、[nfs-utils](https://wiki.linux-nfs.org/wiki/index.php/Nfs-utils)、[Open-iSCSI](https://github.com/open-iscsi/open-iscsi)

### 实时媒体与通信
- SIP：`UDP/TCP/5060`；`TLS/5061`，[RFC 3261](https://www.rfc-editor.org/rfc/rfc3261)
- RTP/RTCP：动态端口范围（常见 `16384–32767`），[RFC 3550](https://www.rfc-editor.org/rfc/rfc3550)
- SRTP：[RFC 3711](https://www.rfc-editor.org/rfc/rfc3711)
- SDP：[RFC 4566](https://www.rfc-editor.org/rfc/rfc4566)
- RTSP：`TCP/554`（RTSP 2.0 [RFC 7826](https://www.rfc-editor.org/rfc/rfc7826)）
- RTMP：`TCP/1935`（Adobe 规范）
- WebRTC：`ICE/STUN/TURN`（STUN：`UDP/3478`；TURN：`TCP/3478/5349`），浏览器栈规范
- HLS：基于 `HTTP`，`IETF draft`/Apple 规范；MPEG‑DASH：`ISO/IEC 23009‑1`
 - 实用参考： [Asterisk](https://www.asterisk.org/)、[FreeSWITCH](https://freeswitch.com/)、[Janus WebRTC](https://janus.conf.meetecho.com/)、[FFmpeg](https://ffmpeg.org/)

### 消息与队列
- MQTT：`TCP/1883`；`TLS/8883`（v3.1.1/v5.0，OASIS 规范）
- MQTT‑SN：基于 `UDP`/`串口` 等，面向低功耗
- AMQP：`TCP/5672`；`TLS/5671`，`OASIS` 规范
- STOMP：`TCP/61613`（常见）
- DDS：`RTPS`/UDP，`OMG` 规范
- Kafka 协议：`TCP/9092`（常见）
 - 实用参考： [Eclipse Mosquitto](https://mosquitto.org/)、[RabbitMQ](https://www.rabbitmq.com/)、[Apache Kafka](https://kafka.apache.org/)

### 远程访问与桌面
- Telnet：`TCP/23`
- SSH：`TCP/22`
- RDP：`TCP/3389`
- VNC：`TCP/5900`（屏幕编号基座）
- X11：`TCP/6000+`
 - 实用参考： [OpenSSH](https://www.openssh.com/)、[xrdp](https://github.com/neutrinolabs/xrdp)、[TigerVNC](https://tigervnc.org/)

### 目录与身份
- LDAP：`TCP/389`；LDAPS：`TCP/636`，[RFC 4511](https://www.rfc-editor.org/rfc/rfc4511)
- Active Directory：基于 `LDAP/Kerberos/DNS`（端口按组件）
 - 实用参考： [OpenLDAP](https://www.openldap.org/)、[Samba AD DC](https://wiki.samba.org/index.php/Active_Directory)、[FreeIPA](https://www.freeipa.org/)

### 物联网与工业
- CoAP：`UDP/5683`；`DTLS/5684`，[RFC 7252](https://www.rfc-editor.org/rfc/rfc7252)
- Zigbee/Z‑Wave/Thread：端口随网关实现，底层 802.15.4
- Modbus/TCP：`TCP/502`
- DNP3：`TCP/20000`
- IEC 60870‑5‑104：`TCP/2404`
- IEC 61850（MMS/GOOSE/SV）：`TCP/102`（MMS）；GOOSE/SV 多用以太网多播
- OPC UA：`TCP/4840`（常见）
- BACnet/IP：`UDP/47808`
 - 实用参考： [libmodbus](https://libmodbus.org/)、[OpenDNP3](https://www.automatak.com/opendnp3/)、[open62541 (OPC UA)](https://open62541.org/)

### P2P 与分布式
- BitTorrent：`TCP/UDP` 端口自定义；`DHT/Kademlia` 依实现
- Tor：`TCP`（SOCKS `9050/9150` 等，具体随部署）
- libp2p：端口与传输按应用配置
 - 实用参考： [Transmission](https://transmissionbt.com/)、[qBittorrent](https://www.qbittorrent.org/)、[Tor Browser](https://www.torproject.org/)

### 打印与周边
- IPP：`TCP/631`；IPPS：`TCP/631`（TLS）
- LPD：`TCP/515`
- AirPrint：基于 `IPP` 与 `mDNS`（`UDP/5353`）。参阅：[Apple AirPrint](https://support.apple.com/zh-cn/HT201311)
 - 实用参考： [CUPS](https://openprinting.github.io/cups/)