# 使用 WebSocket 重构连接的方案

本方案在不破坏现有“自定义二进制协议”的前提下，引入 WebSocket 作为新的传输层，使客户端与服务器能够在 HTTP(S) 通道上通信，便于穿透公司/校园网络、兼容负载均衡/反向代理，并统一走 80/443（WSS）端口，提升部署便利性与稳定性。

目标
- 兼容现有协议：保留当前消息头与负载结构（msg_type/conn_id 等），将其作为 WebSocket 二进制帧的 payload 承载。
- 渐进式落地：服务端同时支持原生 TCP 与 WebSocket；客户端可按需切换（或提供独立版本）。
- 最小依赖：服务端/客户端优先实现“纯 C++”最小握手与帧编解码，避免额外第三方依赖，维持现有静态编译/跨平台特性。
- 可观测性：心跳、超时、连接指标与日志完整可观测。

一、总体架构
- 现状：
  - 客户端通过自定义 TCP 隧道协议与服务端交互；UDP 通过隧道消息 0x03 封装；服务端做 TCP/UDP 双向转发与 IP 替换。
- 引入 WebSocket 后：
  - 客户端→服务端：使用 WebSocket Binary Frame（opcode=0x2）承载当前的二进制消息（0x01/0x02/0x03 等）。
  - 服务端→客户端：同样使用 Binary Frame；保持现有消息格式不变。
  - 连接模型：
    - 方案A（推荐）：一个 WebSocket 长连接上复用多个逻辑连接（依赖消息内的 conn_id 区分）。
    - 方案B（兼容）：仍按“每逻辑连接→一条 WebSocket 连接”建连（迁移简单，但连接数高）。

二、传输层抽象（重构建议）
- 在服务端与客户端内部分别引入传输层接口 IChannel：
  - 接口：
    - int recv_exact(uint8_t* buf, size_t n);
    - int send_all(const uint8_t* buf, size_t n);
    - bool is_open();
    - void close();
  - 实现：
    - TcpChannel：现有的基于 POSIX/WinSock 的收发。
    - WsChannel：底层用 TCP 建立后进行 WebSocket 握手，后续在帧层做编解码，再向上提供与 TcpChannel 一致的“消息级别”读写（对上保留现有协议）。
- TunnelConnection/TunnelServer 等仅依赖 IChannel，不关心底层是 TCP 还是 WS。

三、WebSocket 协议要点（最小实现）
1) 握手（HTTP Upgrade）
- 客户端发送：
  GET /dnf HTTP/1.1\r\n
  Host: example.com\r\n
  Upgrade: websocket\r\n
  Connection: Upgrade\r\n
  Sec-WebSocket-Key: <16字节随机值的Base64>\r\n
  Sec-WebSocket-Version: 13\r\n
  Sec-WebSocket-Protocol: dnf-tunnel-v1\r\n
  \r\n
- 服务端响应：
  HTTP/1.1 101 Switching Protocols\r\n
  Upgrade: websocket\r\n
  Connection: Upgrade\r\n
  Sec-WebSocket-Accept: base64( SHA1( key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" ) )\r\n
  Sec-WebSocket-Protocol: dnf-tunnel-v1\r\n
  \r\n
- 说明：
  - 必须正确计算 Sec-WebSocket-Accept。
  - 可选使用子协议 dnf-tunnel-v1 标识应用层协议版本。

2) 数据帧（Binary）
- 客户端→服务端：必须 mask（掩码）payload；FIN=1，opcode=0x2（Binary）。
- 服务端→客户端：不 mask；FIN=1，opcode=0x2。
- 需处理的要点：
  - 负载长度：7位/16位/64位可变长度编码；
  - 掩码处理：客户端帧 payload 需按 4 字节掩码异或；
  - 控制帧：ping/pong/close；
  - 分片：最小实现可禁止分片（要求 FIN=1），遇到分片按协议聚合后再上抛。
- 心跳：
  - 客户端每 30s 发送 ping；服务端自动回 pong；同时双方跟踪读写超时，超时断线重连。

四、协议映射与复用
- 保持现有自定义消息格式不变：
  - TCP 数据：type=0x01，头(1+4+2)，payload...
  - UDP 数据：type=0x03，头(1+4+2+2+2)，payload...
  - 其他类型：保持原有定义。
- 复用（推荐）：
  - 同一条 WS 链路上，使用 conn_id 区分多条逻辑连接；服务端维护 conn_id→TunnelConnection 的路由表；
  - 新增管理对象 WSSession，负责：
    - 从 WsChannel 读取“应用层消息”（一帧内可携带 1~N 条完整消息，或逐条传输）；
    - 将消息分发给对应的 TunnelConnection；
    - 当 conn_id 首次出现时，创建对应的 TunnelConnection（无需额外 TCP accept）。
- 兼容（过渡期）：服务端保留现有 TCP 模式；客户端可配置切换（raw TCP / WebSocket）。

五、部署与安全
- 强烈建议使用 WSS over TLS（443）：
  - 由 Nginx/Caddy/Envoy 等做 TLS 终止与反向代理，服务端只需处理纯 WS（HTTP 升级）。
- Nginx 示例：

  upstream dnf_tunnel_ws { server 127.0.0.1:33280; }

  server {
      listen 443 ssl http2;
      server_name tunnel.example.com;
      ssl_certificate     /path/fullchain.pem;
      ssl_certificate_key /path/privkey.pem;

      location /dnf {
          proxy_http_version 1.1;
          proxy_set_header Upgrade $http_upgrade;
          proxy_set_header Connection "Upgrade";
          proxy_set_header X-Real-IP $remote_addr;
          proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_read_timeout 3600s;
          proxy_send_timeout 3600s;
          proxy_pass http://dnf_tunnel_ws;
      }
  }

- 注意：
  - 反向代理需放开 WebSocket；
  - idle/read 超时调大，避免长时间无数据被断线；
  - 可按源 IP/子协议/路径做访问控制。

六、实现计划（最小可行）
阶段1：接口与服务端 WS 接入
1) 服务端新增 WsListener（监听 33280 或环境变量指定端口）：
   - 接收 TCP 连接，解析 HTTP Upgrade 请求；
   - 校验头部并返回 101；
   - 将该连接封装为 WsChannel，交由 WSSession 处理。
2) 引入 IChannel 接口 + TcpChannel（薄封装现有 recv/sendall）。
3) 将 TunnelConnection/TunnelServer 改造成使用 IChannel（或增加一个适配层，仅对入口读写抽象）。
4) WSSession：
   - 从 WsChannel 读二进制帧→解包为应用层消息→按 conn_id 路由；
   - 负责 conn_id 生命周期：首次消息创建 TunnelConnection；连接关闭时回收。
5) 兼容：原 TCP 监听保持不变，二者可并行。

阶段2：客户端 WS 传输
1) 新增 WsTransport：
   - 使用 WinSock 实现最小 HTTP Upgrade；
   - 内置 Base64 + SHA1（可使用简洁实现，避免外部库）；
   - 实现 WS 帧编解码、mask、ping/pong、超时；
   - 暴露 send/recv 与现有发送线程对接。
2) 配置：在配置注入器中增加一个可选字段 ws=true/wss=true（或另起一个客户端版本）。
3) 迁移策略：默认仍走 TCP；在受限网络使用 WSS。

阶段3：复用与优化
1) 将当前“每连接一条 TCP”的模式切换为“单 WS 多 conn_id 复用”。
2) 服务器端 WSSession 内引入
   - 写队列/背压：避免单客户端阻塞影响全局；
   - 粘包/分包：应用层消息可以按条写入；
   - 发送聚合：合并小包减少帧开销。
3) 指标与运维：
   - 连接数、活跃 conn_id、带宽、消息速率；
   - 心跳与重连次数；
   - 错误码与异常日志。

七、兼容性与回滚
- 双栈运行：保持 TCP 与 WS 并存，可灰度引流到 WSS。
- 回滚：若 WSS 在特定网络/代理下有问题，客户端可回退到原 TCP。

八、测试清单
- 单元/集成：
  - Sec-WebSocket-Accept 计算与 Base64/SH A1；
  - WS 帧长度边界（7位、16位、64位）；
  - 掩码正确性、ping/pong；
  - 粘包/分包、多消息聚合；
  - 复用：并发 1000+ conn_id；
  - 超时/断线重连；
- 兼容：
  - 直连与经 Nginx 反代；
  - HTTP/1.1 与各类代理；
  - IPv4/IPv6 与域名解析。

九、最小代码骨架（伪代码）
- IChannel：
  class IChannel { public: virtual int recv_exact(uint8_t*, size_t)=0; virtual int send_all(const uint8_t*, size_t)=0; virtual bool is_open()=0; virtual void close()=0; virtual ~IChannel(){} };

- TcpChannel：
  class TcpChannel : public IChannel { int fd; /* wrap recv/send */ };

- WsChannel：
  - 构造时接收 fd（服务端）或目标地址（客户端），完成握手；
  - 读：循环读取 WS 帧头→解析长度/掩码→读取 payload→unmask（若客户端→服务端）→返回应用层数据；
  - 写：将应用层数据封装成二进制帧发送；
  - 处理 ping/pong 与 close；

- WSSession（服务端）：
  - while (chan.is_open()) { read_msg(); switch(msg_type){case 0x01: route_to_tcp(); case 0x03: route_to_udp(); ...} }

十、运维建议
- 强制 WSS 使用 443 并配置正确的 TLS；
- 调大代理与后端的 read_timeout / keepalive；
- 监控连接与消息速率，异常场景自动重启/降级。

附：实现提示
- Base64/SHA1 可选用简洁实现，注意跨平台（Windows/MinGW/MSVC & Linux/GCC）。
- 服务器静态编译时不引入 OpenSSL，TLS 由前置代理完成（Nginx/Caddy）。
- 首期实现可以仅支持 Binary + FIN=1（不分片），逐步完善。

迁移收益
- 更强的网络穿透：经常能穿越公司网、学校网、家庭网的 HTTP/HTTPS 代理限制；
- 更友好的运维：统一 443 端口，支持云厂商/边缘加速；
- 更灵活的拓扑：反向代理/WAF/认证接入成为可能；
- 渐进式改造：与现有 TCP 模式并存，随时回退。
