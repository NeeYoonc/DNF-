/*
 * DNF 隧道 WebSocket 桥接 - 最小可用版本 (服务端)
 * 作用: 将 WebSocket(Binary) 流量桥接到本机 dnf-tunnel-server 的原生 TCP 端口
 * 使用场景: 反向代理/Nginx/Caddy 终止 TLS 后，将 /dnf 路径转发到此进程监听端口
 * 
 * 设计说明:
 * - 该桥接程序并不修改原有 dnf-tunnel-server 的二进制协议
 * - 客户端建立 WebSocket 连接后，直接将自定义二进制消息作为 Binary Frame 发送
 * - 桥接程序完成 HTTP Upgrade 与 WS 帧编解码，将负载透传到后端原生 TCP 端口
 * - 路径映射: GET /dnf/<port> → 连接到 127.0.0.1:<port> (若未提供端口，默认 33223)
 * - 该文件独立构建为: dnf-tunnel-ws-bridge
 *
 * 注意:
 * - 该文件不参与默认 make all 构建，需手动 make ws-bridge
 * - 未实现 TLS，建议由 Nginx/Caddy 负责 TLS 终止与反代
 */

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <map>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

using namespace std;

// =============== 简单日志 ===============
static void log_info(const string& s){ cerr << "[INFO] " << s << "\n"; }
static void log_err(const string& s){ cerr << "[ERROR] " << s << "\n"; }
static void log_debug(const string& s){ cerr << "[DEBUG] " << s << "\n"; }

// =============== 工具: 读写 ===============
static int read_n(int fd, uint8_t* buf, size_t n){
    size_t off = 0;
    while(off < n){
        ssize_t r = recv(fd, buf + off, n - off, 0);
        if(r <= 0) return (int)r;
        off += (size_t)r;
    }
    return (int)off;
}

static int write_n(int fd, const uint8_t* buf, size_t n){
    size_t off = 0;
    while(off < n){
        ssize_t w = send(fd, buf + off, n - off, 0);
        if(w <= 0) return (int)w;
        off += (size_t)w;
    }
    return (int)off;
}

// =============== Base64 ===============
static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static string base64_encode(const uint8_t* data, size_t len){
    string out;
    out.reserve(((len+2)/3)*4);
    for(size_t i=0;i<len;i+=3){
        uint32_t v = data[i] << 16;
        if(i+1 < len) v |= data[i+1] << 8;
        if(i+2 < len) v |= data[i+2];
        out.push_back(B64[(v>>18)&0x3F]);
        out.push_back(B64[(v>>12)&0x3F]);
        if(i+1 < len) out.push_back(B64[(v>>6)&0x3F]); else out.push_back('=');
        if(i+2 < len) out.push_back(B64[v&0x3F]); else out.push_back('=');
    }
    return out;
}

// =============== SHA1 (最小实现) ===============
struct SHA1Ctx { uint32_t h[5]; uint64_t len_bits; uint8_t buf[64]; size_t buf_len; };

static uint32_t rol(uint32_t x, int n){ return (x<<n) | (x>>(32-n)); }

static void sha1_init(SHA1Ctx* c){
    c->h[0]=0x67452301; c->h[1]=0xEFCDAB89; c->h[2]=0x98BADCFE; c->h[3]=0x10325476; c->h[4]=0xC3D2E1F0;
    c->len_bits=0; c->buf_len=0;
}
static void sha1_block(SHA1Ctx* c, const uint8_t* p){
    uint32_t w[80];
    for(int i=0;i<16;i++){
        w[i] = (p[4*i]<<24) | (p[4*i+1]<<16) | (p[4*i+2]<<8) | p[4*i+3];
    }
    for(int i=16;i<80;i++) w[i] = rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    uint32_t a=c->h[0],b=c->h[1],c2=c->h[2],d=c->h[3],e=c->h[4];
    for(int i=0;i<80;i++){
        uint32_t f,k;
        if(i<20){ f=(b&c2)|((~b)&d); k=0x5A827999; }
        else if(i<40){ f=b^c2^d; k=0x6ED9EBA1; }
        else if(i<60){ f=(b&c2)|(b&d)|(c2&d); k=0x8F1BBCDC; }
        else { f=b^c2^d; k=0xCA62C1D6; }
        uint32_t temp = rol(a,5) + f + e + k + w[i];
        e=d; d=c2; c2=rol(b,30); b=a; a=temp;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=c2; c->h[3]+=d; c->h[4]+=e;
}
static void sha1_update(SHA1Ctx* c, const uint8_t* data, size_t len){
    c->len_bits += (uint64_t)len * 8ULL;
    size_t off = 0;
    while(off < len){
        size_t space = 64 - c->buf_len;
        size_t tocpy = min(space, len - off);
        memcpy(c->buf + c->buf_len, data + off, tocpy);
        c->buf_len += tocpy; off += tocpy;
        if(c->buf_len == 64){ sha1_block(c, c->buf); c->buf_len=0; }
    }
}
static void sha1_final(SHA1Ctx* c, uint8_t out[20]){
    // pad: 0x80 + zeros + len_bits (big-endian)
    uint8_t pad0x80 = 0x80; sha1_update(c, &pad0x80, 1);
    uint8_t zero = 0x00; while(c->buf_len != 56){ sha1_update(c, &zero, 1); }
    uint8_t len_be[8];
    for(int i=0;i<8;i++){ len_be[7-i] = (uint8_t)((c->len_bits>>(8*i)) & 0xFF); }
    sha1_update(c, len_be, 8);
    for(int i=0;i<5;i++){
        out[4*i] = (uint8_t)(c->h[i]>>24);
        out[4*i+1] = (uint8_t)(c->h[i]>>16);
        out[4*i+2] = (uint8_t)(c->h[i]>>8);
        out[4*i+3] = (uint8_t)(c->h[i]);
    }
}
static string sha1_hex(const string& s){
    SHA1Ctx c; sha1_init(&c); sha1_update(&c, (const uint8_t*)s.data(), s.size()); uint8_t out[20]; sha1_final(&c,out);
    string hex; hex.reserve(40);
    static const char* H = "0123456789abcdef";
    for(int i=0;i<20;i++){ hex.push_back(H[out[i]>>4]); hex.push_back(H[out[i]&0xF]); }
    return hex;
}
static string sha1_raw(const string& s){
    SHA1Ctx c; sha1_init(&c); sha1_update(&c,(const uint8_t*)s.data(), s.size()); uint8_t out[20]; sha1_final(&c,out);
    return string((char*)out, 20);
}

// =============== WebSocket 握手 ===============
static bool read_http_headers(int fd, string& request_line, map<string,string>& headers, string& path){
    // 读取到空行为止
    string data;
    char buf[1024];
    while(data.find("\r\n\r\n") == string::npos){
        ssize_t r = recv(fd, buf, sizeof(buf), 0);
        if(r <= 0) return false;
        data.append(buf, buf + r);
        if(data.size() > 8192) return false; // 请求头过大
    }
    // 切分请求
    size_t pos = data.find("\r\n");
    if(pos == string::npos) return false;
    request_line = data.substr(0, pos);
    size_t start = pos + 2;
    while(true){
        size_t next = data.find("\r\n", start);
        if(next == string::npos) return false;
        if(next == start) break; // 空行
        string line = data.substr(start, next - start);
        start = next + 2;
        size_t colon = line.find(":");
        if(colon != string::npos){
            string k = line.substr(0, colon);
            string v = line.substr(colon+1);
            // 去空格
            while(!v.empty() && (v[0]==' '||v[0]=='\t')) v.erase(v.begin());
            for(auto& c : k){ if(c>='A'&&c<='Z') c = (char)(c - 'A' + 'a'); }
            headers[k] = v;
        }
    }
    // 解析路径
    // 形如: GET /dnf/33223 HTTP/1.1
    {
        // 基本切分
        size_t sp1 = request_line.find(' ');
        size_t sp2 = request_line.find(' ', sp1==string::npos?0:sp1+1);
        if(sp1 != string::npos && sp2 != string::npos){
            path = request_line.substr(sp1+1, sp2-sp1-1);
        } else path = "/";
    }
    return true;
}

static bool send_http_switching(int fd, const string& sec_key){
    static const string GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    string accept_src = sec_key + GUID;
    string sha = sha1_raw(accept_src);
    string accept = base64_encode((const uint8_t*)sha.data(), sha.size());

    string resp =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + accept + "\r\n"
        "Sec-WebSocket-Protocol: dnf-tunnel-v1\r\n"
        "\r\n";
    return write_n(fd, (const uint8_t*)resp.data(), resp.size()) == (int)resp.size();
}

// =============== WebSocket 帧编解码（最小） ===============
struct WSFrame { bool fin; uint8_t opcode; vector<uint8_t> payload; };

static bool ws_read_frame(int fd, WSFrame& f){
    uint8_t h[2];
    int r = read_n(fd, h, 2);
    if(r <= 0) return false;
    f.fin = (h[0] & 0x80) != 0;
    f.opcode = (uint8_t)(h[0] & 0x0F);
    bool masked = (h[1] & 0x80) != 0;
    uint64_t len = (h[1] & 0x7F);
    if(len == 126){
        uint8_t ext[2]; if(read_n(fd, ext, 2) <= 0) return false;
        len = (ext[0] << 8) | ext[1];
    } else if(len == 127){
        uint8_t ext[8]; if(read_n(fd, ext, 8) <= 0) return false;
        len = 0; for(int i=0;i<8;i++){ len = (len<<8) | ext[i]; }
    }
    uint8_t mask_key[4] = {0,0,0,0};
    if(masked){ if(read_n(fd, mask_key, 4) <= 0) return false; }
    f.payload.resize((size_t)len);
    if(len){ if(read_n(fd, f.payload.data(), (size_t)len) <= 0) return false; }
    if(masked){ for(size_t i=0;i<len;i++){ f.payload[i] ^= mask_key[i%4]; } }
    return true;
}

static bool ws_write_frame(int fd, uint8_t opcode, const uint8_t* data, size_t len){
    vector<uint8_t> out;
    out.reserve(2 + 8 + len);
    uint8_t b0 = 0x80 | (opcode & 0x0F); // FIN=1
    out.push_back(b0);
    if(len < 126){ out.push_back((uint8_t)len); }
    else if(len <= 0xFFFF){ out.push_back(126); out.push_back((uint8_t)(len>>8)); out.push_back((uint8_t)len); }
    else {
        out.push_back(127);
        for(int i=7;i>=0;i--) out.push_back((uint8_t)((len>>(8*i)) & 0xFF));
    }
    // 服务端发给客户端不使用 MASK
    out.insert(out.end(), data, data+len);
    return write_n(fd, out.data(), out.size()) == (int)out.size();
}

static bool ws_write_text(int fd, const string& s){ return ws_write_frame(fd, 0x1, (const uint8_t*)s.data(), s.size()); }
static bool ws_write_binary(int fd, const vector<uint8_t>& v){ return ws_write_frame(fd, 0x2, v.data(), v.size()); }
static bool ws_write_pong(int fd, const vector<uint8_t>& v){ return ws_write_frame(fd, 0xA, v.data(), v.size()); }
static bool ws_write_close(int fd){ return ws_write_frame(fd, 0x8, nullptr, 0); }

// =============== 上游 TCP 连接 ===============
static int connect_upstream(const string& host, int port){
    struct addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
    struct addrinfo* res = nullptr;
    string port_str = to_string(port);
    if(getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for(auto* rp = res; rp; rp = rp->ai_next){
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(fd < 0) continue;
        int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if(rc == 0){ freeaddrinfo(res); return fd; }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return -1;
}

// =============== 会话处理 ===============
static int extract_port_from_path(const string& path, int def_port){
    // 期望 /dnf/<port>
    size_t p = path.find_last_of('/');
    if(p != string::npos){
        string tail = path.substr(p+1);
        if(!tail.empty()){
            int v = 0; for(char c: tail){ if(c<'0'||c>'9'){ v = -1; break; } v = v*10 + (c-'0'); }
            if(v > 0 && v <= 65535) return v;
        }
    }
    return def_port;
}

static void handle_ws_client(int fd){
    string req, path; map<string,string> headers;
    if(!read_http_headers(fd, req, headers, path)){
        log_err("读取HTTP请求失败"); close(fd); return; }
    log_info("请求: " + req);
    string key;
    auto it = headers.find("sec-websocket-key");
    if(it != headers.end()) key = it->second; else { log_err("缺少Sec-WebSocket-Key"); close(fd); return; }
    if(!send_http_switching(fd, key)){
        log_err("发送101失败"); close(fd); return; }

    int target_port = extract_port_from_path(path, 33223);
    int upstream = connect_upstream("127.0.0.1", target_port);
    if(upstream < 0){
        log_err("连接上游失败 127.0.0.1:" + to_string(target_port));
        ws_write_text(fd, "upstream connect failed");
        ws_write_close(fd);
        close(fd);
        return;
    }
    log_info("WebSocket已升级，桥接至 127.0.0.1:" + to_string(target_port));

    atomic<bool> running(true);

    // 线程1：WS -> TCP
    thread t_ws_to_tcp([&](){
        while(running){
            WSFrame f; if(!ws_read_frame(fd, f)){ running=false; break; }
            if(f.opcode == 0x8){ // close
                running=false; break;
            } else if(f.opcode == 0x9){ // ping
                ws_write_pong(fd, f.payload); continue;
            } else if(f.opcode == 0x2 || f.opcode == 0x0){ // binary/cont
                if(!f.fin){
                    // 简单聚合: 读取直到 FIN=1
                    vector<uint8_t> agg = std::move(f.payload);
                    while(true){
                        WSFrame c; if(!ws_read_frame(fd, c)){ running=false; break; }
                        if(c.opcode != 0x0 && c.opcode != 0x2 && c.opcode != 0x9){ /*忽略*/ }
                        agg.insert(agg.end(), c.payload.begin(), c.payload.end());
                        if(c.fin) break;
                    }
                    if(!running) break;
                    if(write_n(upstream, agg.data(), agg.size()) <= 0){ running=false; break; }
                } else {
                    if(!f.payload.empty()){
                        if(write_n(upstream, f.payload.data(), f.payload.size()) <= 0){ running=false; break; }
                    }
                }
            } else {
                // 其他帧忽略
            }
        }
        shutdown(upstream, SHUT_RDWR);
    });

    // 线程2：TCP -> WS
    thread t_tcp_to_ws([&](){
        uint8_t buf[4096];
        while(running){
            ssize_t r = recv(upstream, buf, sizeof(buf), 0);
            if(r <= 0){ running=false; break; }
            if(!ws_write_frame(fd, 0x2, buf, (size_t)r)){ running=false; break; }
        }
        shutdown(fd, SHUT_RDWR);
    });

    t_ws_to_tcp.join();
    t_tcp_to_ws.join();

    close(upstream);
    close(fd);
    log_info("连接结束");
}

// =============== 监听主循环 ===============
int main(int argc, char** argv){
    int listen_port = 33280; // 默认WS端口
    if(argc >= 2){ listen_port = atoi(argv[1]); if(listen_port <= 0) listen_port = 33280; }

    int lfd = socket(AF_INET6, SOCK_STREAM, 0);
    if(lfd < 0){ perror("socket"); return 1; }
    int v6only = 0; setsockopt(lfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    int opt=1; setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in6 addr{}; addr.sin6_family = AF_INET6; addr.sin6_addr = in6addr_any; addr.sin6_port = htons(listen_port);
    if(bind(lfd, (sockaddr*)&addr, sizeof(addr)) < 0){ perror("bind"); close(lfd); return 1; }
    if(listen(lfd, 128) < 0){ perror("listen"); close(lfd); return 1; }

    cerr << "============================================================\n";
    cerr << "DNF WebSocket Bridge (server)\n";
    cerr << "Listen on: " << listen_port << " (IPv4/IPv6 dual-stack)\n";
    cerr << "Path rule : /dnf/<port> => 127.0.0.1:<port> (default:33223)\n";
    cerr << "============================================================\n";

    while(true){
        sockaddr_storage cli{}; socklen_t len=sizeof(cli);
        int cfd = accept(lfd, (sockaddr*)&cli, &len);
        if(cfd < 0){ if(errno==EINTR) continue; perror("accept"); break; }
        thread(handle_ws_client, cfd).detach();
    }

    close(lfd);
    return 0;
}
