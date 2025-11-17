/*
 * DNF 隧道服务器 - C++ 版本 v5.3
 * v5.3更新: 🔥修复游戏服务器连接空闲超时问题 - 启用TCP Keepalive
 *          问题描述: 游戏服务器在运行约9分钟后发送RST断开连接(errno=104: Connection reset by peer)
 *                   分析发现用户正在游戏中,但如果一段时间没操作(看剧情、挂机等)
 *                   服务端→游戏服务器之间没有数据传输,游戏服务器可能检测到TCP空闲而断开
 *                   客户端心跳包只保持客户端↔服务端隧道活跃,游戏服务器不知道心跳包
 *          解决方案: 在连接到游戏服务器时启用TCP Keepalive
 *                   - 60秒无数据后开始探测
 *                   - 每10秒探测一次
 *                   - 3次探测失败后断开
 *          修改位置: connect_to_game_server函数,connect()成功后(约691-700行)
 *          关键优势: - TCP层面保持连接活跃,防止游戏服务器因空闲断开
 *                   - 不依赖应用层数据,适用于用户挂机/无操作场景
 *                   - 与客户端心跳包互补,双重保活机制
 * v5.2更新: 🔥修复多网卡环境下UDP路由问题 - bind到proxy_local_ip而非INADDR_ANY
 *          问题描述: 服务器有多个网卡（如192.168.2.75 + 108.2.2.55）
 *                   游戏服务器在特定网段（如108.2.2.66）
 *                   UDP socket bind到INADDR_ANY时，操作系统可能选择错误的源IP
 *                   导致游戏服务器的UDP响应无法正确路由回代理服务器
 *          解决方案: UDP socket bind到proxy_local_ip（get_local_ip()返回的最佳路由IP）
 *                   确保UDP包从与游戏服务器同网段的网卡发出
 *                   游戏服务器的响应能正确路由回来
 *          修改位置: handle_udp_tunnel函数，UDP socket创建逻辑（约1877-1912行）
 *          关键优势: - 支持多网卡/多IP环境
 *                   - 跨网段UDP转发正常工作
 *                   - 不需要手动配置路由
 *                   - 自动选择最佳网卡
 * v5.1更新: 配合客户端v12.2.0流式转发优化
 *          - recv缓冲区 4KB → 64KB
 *          - socket缓冲区增大到256KB
 *          - 提升吞吐量，降低延迟
 * DNF 隧道服务器 - C++ 版本 v5.0
 * 完全按照Python版本架构重写
 * 支持 TCP + UDP 双协议转发
 * 支持多端口/多游戏服务器
 * v3.4更新: 智能指针重构,修复竞态条件导致的崩溃问题
 * v3.5更新: 修复UDP Tunnel线程悬垂引用bug,使用shared_ptr确保变量生命周期正确
 * v3.5.1更新: UDP Tunnel析构时使用shutdown()唤醒阻塞的recvfrom()
 * v3.5.2更新: TunnelConnection析构时UDP socket也使用shutdown()
 * v3.5.3更新: 修复半关闭后无法销毁对象的bug - TCP socket也要shutdown
 * v3.5.4更新: 添加边界检查和详细崩溃诊断
 * v3.5.5更新: 修复running=false后game_to_client线程继续sendall导致的崩溃
 * v3.5.6更新: 修复析构函数中的死锁bug - 检测当前线程ID,避免线程join自己
 * v3.5.7-v3.5.9: 尝试使用detach+标志位,但无法解决时序问题
 * v3.6.0-v3.6.1: weak_ptr+reset仍然可能死锁
 * v3.6.2更新: 最终方案 - 在线程内检测到死锁时detach并立即退出析构,接受泄漏
 * v3.6.3更新: 修复僵尸线程FD复用bug - detach后等待500ms确保线程退出,防止FD被新连接复用
 * v3.7.0-v3.7.1更新: 尝试各种方案，全部失败 - 时序问题无法解决
 * v3.8.0更新: 最终可靠方案 - 不使用shared_ptr，改用原始指针+手动内存管理
 * v4.5.0更新: 🎯UDP NAT穿透方案 - payload IP替换
 *             问题分析: Raw Socket伪造源IP方案过于复杂,需要路由、ARP配置
 *                      且游戏服务器在内网,响应公网IP的包会路由到网关丢失
 *             新方案: 使用代理服务器IP(192.168.2.75)作为源IP发送UDP
 *                    游戏服务器响应能正常返回代理服务器
 *                    在响应payload中查找并替换代理IP为客户端公网IP
 *                    游戏协议是明文,IP替换安全可靠
 *             核心机制: 1. 记录TCP连接源IP(客户端公网IP: 222.187.12.82)
 *                      2. UDP发送使用普通socket(源IP自动=192.168.2.75)
 *                      3. 响应接收后,替换payload中的192.168.2.75为222.187.12.82
 *                      4. 支持大端序和小端序IP格式
 * v4.6.0更新: 🎯修复UDP源端口问题 - bind到客户端源端口（失败）
 *             问题: 按目标端口创建socket,多个目标端口bind同一源端口冲突
 *             结果: 只有第一个socket成功bind,后续使用随机端口,游戏服务器返回错误端口
 * v4.7.0更新: 🎯重构UDP socket管理架构 - 按源端口创建socket
 *             问题根源: 客户端使用单个UDP socket(bind 5063)向多个目标端口发送
 *                      v4.6.0为每个目标端口创建socket,都尝试bind 5063导致冲突
 *                      第二个socket bind失败,使用系统随机端口(如45952)
 *             解决方案: 彻底重构UDP socket管理
 *                      - 数据结构: udp_sockets[src_port], flow_metadata[(src_port,dst_port)]
 *                      - 每个源端口只创建一个socket并bind
 *                      - 一个接收线程处理该源端口的所有流量
 *                      - 通过recvfrom()的from_addr判断响应来自哪个游戏服务器端口
 *                      - 根据(src_port,dst_port)查找对应conn_id封装响应
 *             结果: 端口正确了(5063),但游戏服务器仍返回7字节格式
 * v4.7.1更新: 🎯扩展7字节UDP响应为18字节格式（错误方案）
 *             问题根源: 游戏服务器检测到通过代理连接(无TCP上下文关联)
 *                      返回简化的7字节格式: 02 [IP:4] [Port:2]
 *                      客户端期望18字节格式,收到7字节后拒绝并持续重试
 *             解决方案: 在代理服务器检测到7字节响应时自动扩展
 *             结果: 错误！通过分析直连抓包发现游戏服务器本就返回7字节，不需要扩展
 * v4.7.2更新: 🎯UDP握手响应IP替换 - 替换为游戏服务器公网IP（错误方案）
 *             解决方案: 将内网IP替换为game_server_ip(1.87.211.199)
 *             结果: 错误！通过分析直连抓包发现应该返回客户端自己的公网IP
 *                  UDP握手响应的作用是NAT穿透验证，回显客户端的公网IP和端口
 * v4.7.3更新: 🎯UDP握手响应IP替换 - 替换为客户端公网IP（正确方案）
 *             问题根源: 游戏服务器UDP握手响应用于NAT穿透验证
 *                      格式: 02 + 客户端公网IP(4字节,DNF字节序) + 客户端端口(2字节)
 *                      游戏服务器在内网，看到的是代理服务器IP(192.168.x.x)
 *                      客户端期望看到自己真实的公网IP才能验证通过
 *             解决方案: 1. 移除v4.7.1的7→18字节扩展逻辑（不需要）
 *                      2. 检测UDP握手响应(0x02开头)
 *                      3. 提取IP字段(DNF字节序)，判断是否内网IP
 *                      4. 如果是内网IP，替换为client_public_ip（TCP连接源IP）
 *             预期效果: 客户端收到自己的公网IP和端口
 *                      验证通过，发送0x05成功确认
 *                      UDP握手完成！
 *             测试结果: ✗ 仍然失败！原因分析见v4.8.0
 * v4.8.0更新: 🎯UDP源IP欺骗 - bind到客户端真实IP而非代理IP（局域网方案）
 *             问题根源: v4.7.3虽然替换了响应payload中的IP，但这不是关键
 *                      真正原因: 游戏服务器根据UDP包的**源IP地址**计算握手响应的最后2字节
 *             解决方案: UDP源IP欺骗（IP Spoofing）
 *                      1. socket创建后设置IP_TRANSPARENT选项（允许bind到非本地IP）
 *                      2. bind时使用client_ipv4（客户端真实IP，来自握手payload）
 *                      3. sendto时UDP包的源IP = 客户端IP而非代理IP
 *             技术细节: 需要root权限或CAP_NET_ADMIN能力
 *             适用场景: ✓ 同一局域网（客户端、代理、游戏服务器在同一网段）
 *                      ✗ 跨网络（响应会被路由到客户端真实网络，代理收不到）
 * v4.9.0更新: 🎯UDP握手响应端口替换 - 支持异地访问（最终完整方案）
 *             算法发现: 通过多次直连抓包分析，逆向出算法：
 *                      **UDP握手响应最后2字节 = UDP源端口（小端序）**
 *                      - 客户端端口5063  → 响应 c7 13 (小端=0x13c7=5063) ✓
 *                      - 客户端端口51003 → 响应 3b c7 (小端=0xc73b=51003) ✓
 *             问题根源: 异地访问时，代理用自己的端口发送UDP
 *                      游戏服务器返回基于代理端口的值
 *                      客户端期望基于自己源端口的值 → 不匹配失败
 *             解决方案: 代理端重新计算最后2字节
 *                      1. 代理用自己的IP和端口发送UDP（正常发送，不做源IP欺骗）
 *                      2. 游戏服务器返回基于代理端口的握手响应
 *                      3. 代理检测UDP握手响应（0x02开头，7字节）
 *                      4. **关键**：直接替换最后2字节为客户端源端口（小端序）
 *                      5. 转发给客户端，客户端验证通过
 *             技术优势: - 无需root权限或特殊能力
 *                      - 支持任意网络拓扑（同一局域网、跨网络、跨地域）
 *                      - 代理可部署在任何位置
 *                      - 算法简单可靠，只需端口值替换
 *             适用场景: ✓ 所有场景（局域网、异地、公网、内网）
 *             测试验证: ✓ 内网直连成功（192.168.2.35 → 192.168.2.106）
 *                      ✓ 算法验证成功（多组IP/端口测试）
 * v4.9.1更新: 🔥修复v4.9.0遗漏问题 - 同时替换IP字段和端口字段
 *             问题发现: v4.9.0实际测试发现，虽然端口替换正确，但客户端仍然失败
 *                      原因：v4.9.0只替换了端口，没有替换IP字段
 *                      握手响应格式: 02 + IP(4字节,DNF字节序) + Port(2字节,小端序)
 *                      - 服务器返回IP=192.168.2.75（代理服务器IP）
 *                      - 客户端期望IP=192.168.2.35（自己的IP）
 *                      - 客户端收到错误IP，继续发送01重试
 *             完整算法: **IP字段 = UDP包源IP**，**端口字段 = UDP包源端口**
 *                      游戏服务器完全基于UDP包源地址（IP:Port）计算响应
 *             v4.9.1方案: 同时替换IP和端口两个字段
 *                      1. 检测UDP握手响应（0x02开头，7字节）
 *                      2. 解析服务器返回的IP（DNF字节序）和端口（小端序）
 *                      3. **关键**：替换IP字段为客户端private_ip（DNF字节序）
 *                      4. **关键**：替换端口字段为客户端源端口（小端序）
 *                      5. 转发给客户端，客户端验证通过
 *             测试验证: v4.9.0测试失败（只替换端口不够）
 *                      v4.9.1测试失败（用错了IP）
 * v4.9.2更新: 💯修复v4.9.1致命错误 - 使用TCP连接源IP而非payload中的IP
 *             问题发现: v4.9.1测试失败，payload替换正确但客户端仍重试
 *                      对比内网直连成功案例：
 *                      - 内网直连: TCP源IP=192.168.2.35, UDP握手响应IP=192.168.2.35 ✓
 *                      - v4.9.1代理: TCP源IP=192.168.2.1, UDP握手响应IP=192.168.2.35 ✗
 *             根本原因: 客户端验证逻辑: **UDP握手响应IP 必须等于 TCP连接源IP**
 *                      v4.9.1用了payload中的private_ip（192.168.2.35）
 *                      但客户端经过NAT后，TCP源IP是网关IP（192.168.2.1）
 *                      客户端验证: 192.168.2.35 != 192.168.2.1 → 失败重试
 *             v4.9.2方案: 使用TCP连接源IP（client_public_ip）
 *                      1. 从TCP连接获取真实源IP（可能经过NAT）
 *                      2. UDP握手响应替换为TCP源IP和客户端源端口
 *                      3. 客户端验证: UDP响应IP == TCP连接IP → 成功！
 *             关键修改: client_private_ip → client_public_ip
 *             测试验证: v4.9.1测试失败（用错IP来源）
 *                      v4.9.2测试失败（游戏服务器验证失败）
 * v5.0更新:  🎯终极方案 - 完整双向IP替换，让游戏服务器认为客户端就是代理服务器
 *             问题根源: 通过抓包分析直连成功案例，发现游戏服务器的验证逻辑：
 *                      **所有层面的IP必须完全一致**
 *                      直连时: TCP源IP=192.168.2.35, UDP源IP=192.168.2.35,
 *                             UDP握手响应payload IP=192.168.2.35 (全部一致✓)
 *                      v4.9.x代理: TCP源IP=192.168.2.1(NAT), UDP源IP=192.168.2.75(代理),
 *                                 TCP payload IP=192.168.2.35(客户端) (三个IP都不同✗)
 *                      游戏服务器验证: UDP源IP == TCP payload中的IP → 不匹配 → 拒绝服务
 *             v5.0完整方案: **双向IP替换 - 让游戏服务器认为所有流量来自代理IP**
 *                      客户端→游戏服务器:
 *                        1. TCP payload中的IP: 192.168.2.35 → 192.168.2.75(代理IP)
 *                        2. UDP payload中的IP: 192.168.2.35 → 192.168.2.75(代理IP)
 *                        3. UDP包源IP: 自然是192.168.2.75(代理bind到INADDR_ANY)
 *                      游戏服务器→客户端:
 *                        4. TCP payload中的IP: 192.168.2.75 → 192.168.2.35(客户端IP)
 *                        5. UDP握手响应中的IP: 192.168.2.75 → 192.168.2.35(客户端IP)
 *             技术实现: 1. TCP转发添加双向IP替换（客户端↔游戏服务器）
 *                      2. UDP已有替换逻辑，修改替换方向（客户端IP→代理IP）
 *                      3. UDP握手响应替换（代理IP→客户端IP）
 *             关键优势: - 无需root权限（不使用IP_TRANSPARENT）
 *                      - 支持跨网络、跨地域部署
 *                      - 游戏服务器看到的所有IP都是代理IP（一致性验证通过）
 *                      - 客户端看到的所有IP都是自己的IP（无感知）
 *             实现完成: ✅ TCP双向IP替换 (TunnelConnection类)
 *                      ✅ UDP双向IP替换 (handle_udp_tunnel函数)
 *                      ✅ 自动获取代理本地IP (get_local_ip函数)
 *                      ✅ TCP源IP到真实IPv4映射 (client_ip_map)
 *                      ✅ IPv4/IPv6双栈支持，正确提取TCP源IP
 *             工作流程: 1. 客户端建立TCP连接（可能在UDP tunnel之前）
 *                      2. 客户端建立UDP tunnel，发送真实IPv4
 *                      3. 服务器存储 TCP源IP → 真实IPv4 映射
 *                      4. TCP转发时动态查询映射，获取真实IPv4
 *                      5. 所有TCP/UDP payload双向替换IP
 *             关键机制: - TCP连接持有映射指针，支持动态查询
 *                      - 首次查询后缓存结果，避免重复查询
 *                      - 兼容TCP连接早于UDP tunnel建立的情况
 *             测试验证: v4.9.2测试失败（游戏服务器拒绝服务）
 *                      v5.0已完整实现（等待测试验证）
 * 编译: g++ -O2 -pthread tcp_tunnel_server.cpp -o dnf-tunnel-server
 * 静态编译: g++ -O2 -static -pthread tcp_tunnel_server.cpp -o dnf-tunnel-server
 */

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <csignal>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <execinfo.h>
#include "tcp_config_server.h"

using namespace std;

// 前向声明Logger类
class Logger;

// ==================== 配置 ====================
// 单个服务器配置
struct ServerConfig {
    string name = "默认服务器";
    int listen_port = 33223;
    string game_server_ip = "192.168.2.110";
    int max_connections = 100;
};

// 全局配置
// API配置
struct ApiConfig {
    bool enabled = true;
    int port = 33231;
    string tunnel_server_ip = "192.168.2.75";
};

struct GlobalConfig {
    vector<ServerConfig> servers;
    string log_level = "INFO";
    ApiConfig api_config;
};

// ==================== 日志工具 ====================
class Logger {
private:
    static ofstream log_file;
    static mutex log_mutex;
    static bool file_enabled;
    static string current_log_level;
    static string log_dir;           // 日志目录
    static string current_date;      // 当前日志日期 (格式: YYYYMMDD)
    static bool auto_rotate;         // 是否启用自动日志轮转

    // 获取当前日期字符串 (北京时间)
    static string get_current_date() {
        auto now = chrono::system_clock::now();
        auto beijing_time = chrono::system_clock::to_time_t(now + chrono::hours(8));
        stringstream ss;
        ss << put_time(gmtime(&beijing_time), "%Y%m%d");
        return ss.str();
    }

    // 生成日志文件名
    static string generate_log_filename(const string& date) {
        return log_dir + "/server_log_" + date + ".txt";
    }

    // 轮转日志文件
    static void rotate_log_file() {
        string new_date = get_current_date();

        if (new_date == current_date) {
            return;  // 日期未变化，无需轮转
        }

        // 关闭旧日志文件
        if (log_file.is_open()) {
            stringstream ss;
            auto now = chrono::system_clock::now();
            auto beijing_time = chrono::system_clock::to_time_t(now + chrono::hours(8));
            auto ms = chrono::duration_cast<chrono::milliseconds>(
                now.time_since_epoch()) % 1000;

            ss << put_time(gmtime(&beijing_time), "%Y-%m-%d %H:%M:%S")
               << "." << setfill('0') << setw(3) << ms.count()
               << " [INFO] 日志文件轮转: 关闭旧日志，日期从 " << current_date << " 切换到 " << new_date;

            string log_line = ss.str();
            log_file << log_line << endl;
            log_file.flush();
            log_file.close();

            cout << log_line << endl;
        }

        // 打开新日志文件
        current_date = new_date;
        string new_filename = generate_log_filename(current_date);
        log_file.open(new_filename, ios::out | ios::app);

        if (log_file.is_open()) {
            auto now = chrono::system_clock::now();
            auto beijing_time = chrono::system_clock::to_time_t(now + chrono::hours(8));
            auto ms = chrono::duration_cast<chrono::milliseconds>(
                now.time_since_epoch()) % 1000;

            stringstream ss;
            ss << put_time(gmtime(&beijing_time), "%Y-%m-%d %H:%M:%S")
               << "." << setfill('0') << setw(3) << ms.count()
               << " [INFO] 新日志文件已创建(北京时间): " << new_filename;

            string log_line = ss.str();
            cout << log_line << endl;
            log_file << log_line << endl;
            log_file.flush();
        } else {
            cerr << "错误: 无法创建新日志文件: " << new_filename << endl;
            file_enabled = false;
        }
    }

public:
    static void set_log_level(const string& level) {
        current_log_level = level;
    }

    static void init(const string& filename) {
        // 从文件名中提取日志目录
        size_t last_slash = filename.find_last_of("/\\");
        if (last_slash != string::npos) {
            log_dir = filename.substr(0, last_slash);
        } else {
            log_dir = "log";  // 默认目录
        }

        // 启用自动轮转
        auto_rotate = true;
        current_date = get_current_date();

        // 使用日期命名的日志文件
        string dated_filename = generate_log_filename(current_date);

        log_file.open(dated_filename, ios::out | ios::app);
        if (log_file.is_open()) {
            file_enabled = true;
            // 不能在这里调用log()因为会死锁，直接输出
            auto now = chrono::system_clock::now();
            // 强制使用北京时间(UTC+8)
            auto beijing_time = chrono::system_clock::to_time_t(now + chrono::hours(8));
            auto ms = chrono::duration_cast<chrono::milliseconds>(
                now.time_since_epoch()) % 1000;

            stringstream ss;
            ss << put_time(gmtime(&beijing_time), "%Y-%m-%d %H:%M:%S")
               << "." << setfill('0') << setw(3) << ms.count()
               << " [INFO] 日志文件已初始化(北京时间, 自动按天分割): " << dated_filename;

            string log_line = ss.str();
            cout << log_line << endl;
            log_file << log_line << endl;
            log_file.flush();
        } else {
            cerr << "警告: 无法打开日志文件: " << dated_filename << endl;
        }
    }

    static void close() {
        lock_guard<mutex> lock(log_mutex);
        if (log_file.is_open()) {
            log_file.close();
            file_enabled = false;
        }
    }

    static void info(const string& msg) {
        log("INFO", msg);
    }

    static void error(const string& msg) {
        log("ERROR", msg);
    }

    static void warning(const string& msg) {
        log("WARN", msg);
    }

    static void debug(const string& msg) {
        log("DEBUG", msg);
    }

private:
    static void log(const string& level, const string& msg) {
        // 日志级别过滤: ERROR(3) > WARN(2) > INFO(1) > DEBUG(0)
        int level_priority = 0;
        if (level == "DEBUG") level_priority = 0;
        else if (level == "INFO") level_priority = 1;
        else if (level == "WARN") level_priority = 2;
        else if (level == "ERROR") level_priority = 3;

        int current_priority = 0;
        if (current_log_level == "DEBUG") current_priority = 0;
        else if (current_log_level == "INFO") current_priority = 1;
        else if (current_log_level == "WARN") current_priority = 2;
        else if (current_log_level == "ERROR") current_priority = 3;

        // 如果当前日志级别低于设定级别，不输出
        if (level_priority < current_priority) return;

        auto now = chrono::system_clock::now();
        // 强制使用北京时间(UTC+8)
        auto beijing_time = chrono::system_clock::to_time_t(now + chrono::hours(8));
        auto ms = chrono::duration_cast<chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        stringstream ss;
        ss << put_time(gmtime(&beijing_time), "%Y-%m-%d %H:%M:%S")
           << "." << setfill('0') << setw(3) << ms.count()
           << " [" << level << "] " << msg;

        string log_line = ss.str();

        // 输出到控制台和文件
        lock_guard<mutex> lock(log_mutex);

        // 检查是否需要轮转日志文件（每天0点自动切换）
        if (auto_rotate && file_enabled) {
            rotate_log_file();
        }

        cout << log_line << endl;
        if (file_enabled && log_file.is_open()) {
            log_file << log_line << endl;
            log_file.flush();  // 立即刷新，确保日志写入
        }
    }
};

// 静态成员初始化
ofstream Logger::log_file;
mutex Logger::log_mutex;
bool Logger::file_enabled = false;
string Logger::current_log_level = "INFO";
string Logger::log_dir = "log";
string Logger::current_date = "";
bool Logger::auto_rotate = true;

// ==================== IP替换辅助函数 ====================
// 在payload中查找并替换IP地址(支持大端序和小端序)
// payload: 数据载荷
// payload_len: 数据长度
// old_ip: 要替换的IP地址(如"192.168.2.75")
// new_ip: 新的IP地址(如"222.187.12.82")
// conn_id: 连接ID（用于日志）
// session_uuid: 会话UUID（用于日志）
// 返回: 替换次数
int replace_ip_in_payload(uint8_t* payload, size_t payload_len,
                         const string& old_ip, const string& new_ip,
                         int conn_id = 0, const string& session_uuid = "") {
    // 生成日志前缀
    string log_prefix;
    if (conn_id > 0 && !session_uuid.empty()) {
        log_prefix = "[连接" + to_string(conn_id) + "|" + session_uuid + "][IP替换] ";
    } else if (conn_id > 0) {
        log_prefix = "[连接" + to_string(conn_id) + "][IP替换] ";
    } else if (!session_uuid.empty()) {
        log_prefix = "[" + session_uuid + "][IP替换] ";
    } else {
        log_prefix = "[IP替换] ";
    }

    // 检查payload是否足够大(至少4字节才可能包含IP)
    if (payload_len < 4) {
        Logger::debug(log_prefix + "payload太小(" + to_string(payload_len) +
                     "字节),跳过IP替换");
        return 0;
    }

    // 将IP字符串转换为字节
    struct in_addr old_addr, new_addr;
    if (inet_pton(AF_INET, old_ip.c_str(), &old_addr) != 1 ||
        inet_pton(AF_INET, new_ip.c_str(), &new_addr) != 1) {
        Logger::error(log_prefix + "IP地址格式错误: " + old_ip + " -> " + new_ip);
        return 0;
    }

    // 提取IP的4个字节(网络字节序,大端序)
    uint8_t* old_bytes = (uint8_t*)&old_addr.s_addr;
    uint8_t* new_bytes = (uint8_t*)&new_addr.s_addr;

    // 构造各种格式
    uint32_t old_ip_be = old_addr.s_addr;  // 大端序(网络字节序)
    uint32_t new_ip_be = new_addr.s_addr;

    // DNF逐字节反向格式: a.b.c.d -> d c b a
    // 修复v4.5.4: 字节序列[d c b a]在小端系统读取为uint32_t时，需要按正序组合
    uint32_t old_ip_reversed = (old_bytes[0] << 24) | (old_bytes[1] << 16) |
                               (old_bytes[2] << 8) | old_bytes[3];
    uint32_t new_ip_reversed = (new_bytes[0] << 24) | (new_bytes[1] << 16) |
                               (new_bytes[2] << 8) | new_bytes[3];

    int replace_count = 0;

    // ===== 详细调试信息 =====
    char debug_buf[200];
    sprintf(debug_buf, "调试: old_bytes=[%02x,%02x,%02x,%02x] old_ip_be=0x%08x old_ip_reversed=0x%08x",
            old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3],
            old_ip_be, old_ip_reversed);
    Logger::debug(log_prefix + string(debug_buf));

    // 打印查找的目标
    if (payload_len >= 4) {
        char hex[100];
        sprintf(hex, "%02x %02x %02x %02x (大端) / %02x %02x %02x %02x (DNF反向)",
                old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3],
                old_bytes[3], old_bytes[2], old_bytes[1], old_bytes[0]);
        Logger::debug(log_prefix + "查找IP " + old_ip + " 格式: " + string(hex));

        // 打印payload前64字节
        string payload_hex = "";
        for (size_t i = 0; i < min((size_t)64, payload_len); i++) {
            char hbuf[4];
            sprintf(hbuf, "%02x ", payload[i]);
            payload_hex += hbuf;
            if ((i + 1) % 16 == 0) payload_hex += "\n                    ";
        }
        Logger::debug(log_prefix + "Payload(" + to_string(payload_len) + "字节):\n                    " + payload_hex);
    }

    // 扫描payload,查找并替换IP
    for (size_t i = 0; i + 3 < payload_len; i++) {
        uint32_t* ip_ptr = (uint32_t*)(payload + i);
        uint32_t ip_value = *ip_ptr;

        // 详细调试：打印每个位置的扫描结果（只打印前10个位置）
        if (i < 10 && payload_len <= 20) {
            char scan_buf[150];
            sprintf(scan_buf, "扫描位置%zu: [%02x %02x %02x %02x] = 0x%08x (大端匹配:%s DNF匹配:%s)",
                    i, payload[i], payload[i+1], payload[i+2], payload[i+3], ip_value,
                    (ip_value == old_ip_be ? "YES" : "no"),
                    (ip_value == old_ip_reversed ? "YES" : "no"));
            Logger::debug(log_prefix + string(scan_buf));
        }

        // 检查大端序(网络字节序)匹配
        if (ip_value == old_ip_be) {
            *ip_ptr = new_ip_be;
            replace_count++;
            Logger::info(log_prefix + "位置" + to_string(i) + " 大端序: " +
                         old_ip + " -> " + new_ip);
            i += 3;
        }
        // 检查DNF逐字节反向格式匹配
        else if (ip_value == old_ip_reversed) {
            *ip_ptr = new_ip_reversed;
            replace_count++;
            Logger::info(log_prefix + "位置" + to_string(i) + " DNF逐字节反向: " +
                         old_ip + " -> " + new_ip);
            i += 3;
        }
    }

    if (replace_count > 0) {
        Logger::info(log_prefix + "✓ 完成: " + old_ip + " -> " + new_ip +
                    " (替换" + to_string(replace_count) + "处)");
    } else {
        Logger::info(log_prefix + "✗ 未找到IP " + old_ip + " (payload=" +
                    to_string(payload_len) + "字节)");
    }

    return replace_count;
}

// 获取本机在指定网络上的本地IP地址
// 通过连接到目标服务器(不实际发送数据)来获取本地IP
string get_local_ip(const string& target_ip) {
    try {
        // 创建一个临时UDP socket
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            return "";
        }

        // 连接到目标IP(UDP不会实际建立连接,只是选择路由)
        struct sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(9);  // 任意端口
        inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            close(sock);
            return "";
        }

        // 获取本地socket地址
        struct sockaddr_in local_addr{};
        socklen_t addr_len = sizeof(local_addr);
        if (getsockname(sock, (struct sockaddr*)&local_addr, &addr_len) < 0) {
            close(sock);
            return "";
        }

        close(sock);

        // 转换为字符串
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
        return string(ip_str);

    } catch (...) {
        return "";
    }
}

// ==================== TCP 连接管理 ====================
class TunnelConnection : public enable_shared_from_this<TunnelConnection> {
private:
    int conn_id;
    int client_fd;
    int game_fd;
    string game_server_ip;
    int game_port;
    atomic<bool> running;
    string session_uuid;  // 客户端会话UUID，用于唯一标识客户端

    // 线程 - 使用智能指针自动管理
    shared_ptr<thread> client_to_game_thread;
    shared_ptr<thread> game_to_client_thread;
    map<int, shared_ptr<thread>> udp_threads;

    // v5.0: IP替换相关 (必须在线程之后声明，匹配构造函数初始化顺序)
    string client_real_ip;     // 客户端真实IP（从payload提取）
    string proxy_local_ip;     // 代理服务器本地IP
    string tcp_source_ip;      // TCP连接源IP（用于动态查询映射）
    map<string, string>* client_ip_map_ptr;  // 指向TunnelServer的IP映射
    mutex* ip_map_mutex_ptr;   // 指向TunnelServer的IP映射互斥锁

    // UDP相关
    map<int, int> udp_sockets;  // dst_port -> udp_socket
    mutex udp_mutex;

    // v5.0: 动态获取客户端真实IP（从映射中查询）
    string get_client_real_ip() {
        if (!client_real_ip.empty()) {
            return client_real_ip;  // 已有缓存
        }
        if (tcp_source_ip.empty() || !client_ip_map_ptr || !ip_map_mutex_ptr) {
            return "";  // 无法查询
        }

        lock_guard<mutex> lock(*ip_map_mutex_ptr);
        auto it = client_ip_map_ptr->find(tcp_source_ip);
        if (it != client_ip_map_ptr->end()) {
            client_real_ip = it->second;  // 缓存结果
            Logger::debug("[连接" + to_string(conn_id) + "|" + session_uuid + "] 动态获取客户端真实IP: " + client_real_ip);
            return client_real_ip;
        }
        return "";
    }

    // 格式化连接标识符（包含conn_id和session_uuid）
    string conn_id_str() const {
        if (session_uuid.empty()) {
            return "[连接" + to_string(conn_id) + "]";
        }
        return "[连接" + to_string(conn_id) + "|" + session_uuid + "]";
    }

public:
    TunnelConnection(int cid, int cfd, const string& game_ip, int gport,
                     const string& client_ip = "", const string& proxy_ip = "",
                     const string& tcp_src_ip = "",
                     map<string, string>* ip_map = nullptr,
                     mutex* ip_mutex = nullptr,
                     const string& sess_uuid = "")
        : conn_id(cid), client_fd(cfd), game_fd(-1),
          game_server_ip(game_ip), game_port(gport),
          running(false), session_uuid(sess_uuid), client_to_game_thread(nullptr),
          game_to_client_thread(nullptr),
          client_real_ip(client_ip), proxy_local_ip(proxy_ip),
          tcp_source_ip(tcp_src_ip), client_ip_map_ptr(ip_map),
          ip_map_mutex_ptr(ip_mutex) {
        Logger::debug("[连接" + to_string(conn_id) + "|" + session_uuid + "] TunnelConnection对象已创建");
    }

    ~TunnelConnection() {
        Logger::debug(conn_id_str() + " 开始销毁TunnelConnection对象");
        stop();

        // **关键修复v3.5.3**: 先shutdown所有sockets(TCP+UDP),让所有阻塞的recv()调用返回
        Logger::debug(conn_id_str() + " shutdown所有sockets以唤醒阻塞线程");

        // 1. shutdown TCP sockets (游戏和客户端)
        if (game_fd >= 0) {
            Logger::debug(conn_id_str() + " shutdown游戏服务器socket");
            shutdown(game_fd, SHUT_RDWR);  // 唤醒阻塞在game_fd上的recv()
        }
        if (client_fd >= 0) {
            Logger::debug(conn_id_str() + " shutdown客户端socket");
            shutdown(client_fd, SHUT_RDWR);  // 唤醒阻塞在client_fd上的recv()
        }

        // 2. shutdown UDP sockets
        {
            lock_guard<mutex> lock(udp_mutex);
            for (auto& pair : udp_sockets) {
                if (pair.second >= 0) {
                    Logger::debug(conn_id_str() + "|UDP:" + to_string(pair.first) + " shutdown UDP socket");
                    shutdown(pair.second, SHUT_RDWR);  // 唤醒阻塞的recvfrom()
                }
            }
        }

        // 3. **v3.8.0**: 不等待线程，直接detach
        // 因为线程只持有原始指针，不会触发析构，可以安全detach
        // running=false + shutdown确保线程会很快退出
        Logger::debug(conn_id_str() + " detach所有线程...");

        if (client_to_game_thread && client_to_game_thread->joinable()) {
            client_to_game_thread->detach();
            Logger::debug(conn_id_str() + " 已detach客户端→游戏线程");
        }

        if (game_to_client_thread && game_to_client_thread->joinable()) {
            game_to_client_thread->detach();
            Logger::debug(conn_id_str() + " 已detach游戏→客户端线程");
        }

        for (auto& pair : udp_threads) {
            if (pair.second && pair.second->joinable()) {
                pair.second->detach();
                Logger::debug(conn_id_str() + "|UDP:" + to_string(pair.first) + " 已detach UDP线程");
            }
        }

        // **v3.8.0关键**: 等待一段时间确保线程完全退出后再关闭socket
        // 这样避免僵尸线程访问已关闭的fd
        Logger::debug(conn_id_str() + " 等待200ms确保detached线程退出...");
        this_thread::sleep_for(chrono::milliseconds(200));

        // 4. 所有线程已退出,现在close所有socket文件描述符
        Logger::debug(conn_id_str() + " 关闭所有socket文件描述符");

        {
            lock_guard<mutex> lock(udp_mutex);
            for (auto& pair : udp_sockets) {
                if (pair.second >= 0) {
                    Logger::debug(conn_id_str() + "|UDP:" + to_string(pair.first) + " close UDP socket fd=" + to_string(pair.second));
                    close(pair.second);
                    pair.second = -1;
                }
            }
        }

        if (game_fd >= 0) {
            Logger::debug(conn_id_str() + " close游戏服务器socket fd=" + to_string(game_fd));
            close(game_fd);
            game_fd = -1;
        }
        if (client_fd >= 0) {
            Logger::debug(conn_id_str() + " close客户端socket fd=" + to_string(client_fd));
            close(client_fd);
            client_fd = -1;
        }

        Logger::debug(conn_id_str() + " TunnelConnection对象已销毁");
    }

    bool start() {
        try {
            Logger::debug(conn_id_str() + " 开始启动连接");

            // 使用 getaddrinfo() 解析游戏服务器地址（支持域名/IPv4/IPv6）
            struct addrinfo hints{}, *result = nullptr, *rp = nullptr;
            hints.ai_family = AF_UNSPEC;      // 允许IPv4或IPv6
            hints.ai_socktype = SOCK_STREAM;  // TCP socket
            hints.ai_flags = 0;
            hints.ai_protocol = IPPROTO_TCP;

            string port_str = to_string(game_port);
            int ret = getaddrinfo(game_server_ip.c_str(), port_str.c_str(), &hints, &result);
            if (ret != 0) {
                Logger::error(conn_id_str() + " DNS解析失败: " +
                             game_server_ip + " (错误: " + gai_strerror(ret) + ")");
                return false;
            }

            Logger::debug(conn_id_str() + " DNS解析成功: " + game_server_ip);

            // 尝试连接所有解析结果
            int flag = 1;  // TCP_NODELAY标志
            for (rp = result; rp != nullptr; rp = rp->ai_next) {
                game_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (game_fd < 0) {
                    continue;
                }

                Logger::debug(conn_id_str() + " 游戏服务器socket已创建 fd=" +
                             to_string(game_fd) + " (协议: " +
                             (rp->ai_family == AF_INET ? "IPv4" : "IPv6") + ")");

                // 禁用Nagle算法
                setsockopt(game_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

                // v12.2.0: 增大socket缓冲区，配合客户端流式转发
                int buf_size = 262144;  // 256KB
                setsockopt(game_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
                setsockopt(game_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

                Logger::debug(conn_id_str() + " 已设置TCP_NODELAY + 256KB缓冲区");

                Logger::debug(conn_id_str() + " 正在连接游戏服务器 " +
                             game_server_ip + ":" + to_string(game_port));

                if (connect(game_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
                    // 连接成功
                    Logger::debug(conn_id_str() + " 成功连接到游戏服务器");

                    // v5.3: 启用TCP Keepalive，防止游戏服务器因空闲超时断开连接
                    int keepalive = 1;
                    if (setsockopt(game_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
                        Logger::warning(conn_id_str() + " 设置SO_KEEPALIVE失败: " +
                                      string(strerror(errno)));
                    }

                    // 设置keepalive参数
                    int keepidle = 60;     // 60秒无数据后开始探测
                    int keepinterval = 10; // 每10秒探测一次
                    int keepcount = 3;     // 3次探测失败后断开

                    setsockopt(game_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
                    setsockopt(game_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepinterval, sizeof(keepinterval));
                    setsockopt(game_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcount, sizeof(keepcount));

                    Logger::info(conn_id_str() + " ✓ TCP Keepalive已启用 " +
                               "(idle=" + to_string(keepidle) + "s, " +
                               "interval=" + to_string(keepinterval) + "s, " +
                               "count=" + to_string(keepcount) + ")");

                    break;
                }

                // 连接失败，关闭socket并尝试下一个地址
                Logger::debug(conn_id_str() + " 连接尝试失败 (errno=" +
                             to_string(errno) + ": " + strerror(errno) + ")，尝试下一个地址");
                close(game_fd);
                game_fd = -1;
            }

            freeaddrinfo(result);

            if (game_fd < 0 || rp == nullptr) {
                Logger::error(conn_id_str() + " 连接游戏服务器失败: " +
                             game_server_ip + ":" + to_string(game_port) + " (所有地址均失败)");
                return false;
            }

            // 客户端socket也禁用Nagle并增大缓冲区
            setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
            int buf_size = 262144;  // 256KB
            setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
            setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

            Logger::info(conn_id_str() + " 已连接到游戏服务器 " +
                        game_server_ip + ":" + to_string(game_port) + " (TCP_NODELAY)");

            running = true;

            // 启动双向转发线程（与Python版本完全一致）
            // **v3.8.0终极方案**: 使用原始指针，避免shared_ptr的生命周期问题
            // 线程不持有对象所有权，只是借用指针
            Logger::debug(conn_id_str() + " 启动客户端→游戏转发线程");
            TunnelConnection* raw_ptr = this;
            client_to_game_thread = make_shared<thread>([raw_ptr]() {
                raw_ptr->forward_client_to_game();
            });

            Logger::debug(conn_id_str() + " 启动游戏→客户端转发线程");
            game_to_client_thread = make_shared<thread>([raw_ptr]() {
                raw_ptr->forward_game_to_client();
            });

            Logger::debug(conn_id_str() + " 连接启动完成，双向转发已开始");
            return true;

        } catch (exception& e) {
            Logger::error(conn_id_str() + " 启动失败: " + string(e.what()));
            return false;
        }
    }

    void stop() {
        running = false;
    }

    bool is_running() const {
        return running;
    }

private:
    // 完整实现sendall（确保所有数据发送完成）
    bool sendall(int fd, const uint8_t* data, int len) {
        // v5.1: 检查fd有效性，防止向已关闭的socket发送数据导致崩溃
        if (fd < 0) {
            Logger::error(conn_id_str() + " sendall失败: fd=" + to_string(fd) + " 无效");
            return false;
        }

        int sent = 0;
        while (sent < len) {
            int ret = send(fd, data + sent, len - sent, 0);
            if (ret <= 0) {
                return false;
            }
            sent += ret;
        }
        return true;
    }

    // 线程1：转发客户端→游戏服务器（完全按照Python版本）
    void forward_client_to_game() {
        vector<uint8_t> buffer;
        uint8_t recv_buf[65536];  // v12.2.0: 增大到64KB，配合流式转发

        Logger::debug(conn_id_str() + " 客户端→游戏转发线程已启动");

        try {
            while (running) {
                // recv(4096) - 与Python版本一致
                int n = recv(client_fd, recv_buf, sizeof(recv_buf), 0);
                if (n <= 0) {
                    if (n == 0) {
                        Logger::info(conn_id_str() + " 客户端正常断开 (recv返回0)");
                    } else {
                        int err = errno;
                        Logger::info(conn_id_str() + " 客户端连接错误 (recv返回" + to_string(n) +
                                   ", errno=" + to_string(err) + ": " + strerror(err) + ")");
                    }
                    running = false;
                    break;
                }

                Logger::debug(conn_id_str() + " 从客户端收到隧道数据 " + to_string(n) + "字节");

                // 添加到缓冲区
                buffer.insert(buffer.end(), recv_buf, recv_buf + n);

                // 解析协议：msg_type(1) + conn_id(4) + ...
                while (buffer.size() >= 5 && running) {
                    uint8_t msg_type = buffer[0];
                    uint32_t msg_conn_id = ntohl(*(uint32_t*)&buffer[1]);

                    if (msg_conn_id != (uint32_t)conn_id) {
                        Logger::warning(conn_id_str() + " 收到错误的连接ID: " +
                                      to_string(msg_conn_id));
                        running = false;
                        break;
                    }

                    if (msg_type == 0x01) {  // TCP数据消息
                        if (buffer.size() < 7) break;

                        uint16_t data_len = ntohs(*(uint16_t*)&buffer[5]);
                        if (buffer.size() < static_cast<size_t>(7 + data_len)) break;

                        // 提取payload
                        vector<uint8_t> payload(buffer.begin() + 7, buffer.begin() + 7 + data_len);
                        buffer.erase(buffer.begin(), buffer.begin() + 7 + data_len);

                        // v5.0: TCP payload IP替换（客户端IP → 代理IP）
                        // 动态获取客户端真实IP（可能在UDP tunnel之后才可用）
                        string real_ip = get_client_real_ip();
                        if (!real_ip.empty() && !proxy_local_ip.empty()) {
                            int replaced = replace_ip_in_payload(
                                const_cast<uint8_t*>(payload.data()),
                                payload.size(),
                                real_ip,
                                proxy_local_ip,
                                conn_id,
                                session_uuid
                            );
                            if (replaced > 0) {
                                Logger::debug(conn_id_str() + " TCP已替换IP: " +
                                            real_ip + " -> " + proxy_local_ip +
                                            " (替换" + to_string(replaced) + "处)");
                            }
                        }

                        // v5.1: 转发前检查连接状态和socket有效性
                        if (!running || game_fd < 0) {
                            Logger::info(conn_id_str() + " 连接已关闭 (running=" +
                                       string(running ? "true" : "false") + ", game_fd=" +
                                       to_string(game_fd) + ")，停止转发");
                            running = false;
                            break;
                        }

                        // 转发到游戏服务器 - sendall
                        if (!sendall(game_fd, payload.data(), payload.size())) {
                            int err = errno;
                            Logger::error(conn_id_str() + " 发送到游戏服务器失败 (errno=" +
                                        to_string(err) + ": " + strerror(err) + ")");

                            // 如果是EPIPE(32)或连接被重置，说明游戏socket已关闭
                            if (err == EPIPE || err == ECONNRESET || err == ENOTCONN) {
                                Logger::info(conn_id_str() + " 游戏socket已关闭，停止转发");
                                running = false;
                            }
                            break;
                        }

                        // 打印载荷预览（前16字节）
                        string hex_preview = "";
                        for (size_t i = 0; i < min((size_t)16, payload.size()); i++) {
                            char buf[4];
                            sprintf(buf, "%02x ", payload[i]);
                            hex_preview += buf;
                        }

                        Logger::debug(conn_id_str() + " 客户端→游戏: " +
                                    to_string(payload.size()) + "字节 载荷:" + hex_preview);
                    }
                    else if (msg_type == 0x02) {  // v12.3.9: 心跳消息
                        if (buffer.size() < 7) break;

                        Logger::debug(conn_id_str() + " 💓 收到心跳包");

                        // 回复心跳包(保持连接双向活跃)
                        uint8_t heartbeat_reply[7];
                        heartbeat_reply[0] = 0x02;
                        *(uint32_t*)&heartbeat_reply[1] = htonl(conn_id);
                        *(uint16_t*)&heartbeat_reply[5] = htons(0);
                        send(client_fd, (char*)heartbeat_reply, 7, 0);

                        buffer.erase(buffer.begin(), buffer.begin() + 7);
                    }
                    else if (msg_type == 0x03) {  // UDP消息
                        if (buffer.size() < 11) break;

                        uint16_t src_port = ntohs(*(uint16_t*)&buffer[5]);
                        uint16_t dst_port = ntohs(*(uint16_t*)&buffer[7]);
                        uint16_t data_len = ntohs(*(uint16_t*)&buffer[9]);

                        if (buffer.size() < static_cast<size_t>(11 + data_len)) break;

                        vector<uint8_t> payload(buffer.begin() + 11, buffer.begin() + 11 + data_len);
                        buffer.erase(buffer.begin(), buffer.begin() + 11 + data_len);

                        // 转发UDP数据
                        forward_udp_to_game(src_port, dst_port, payload);
                    }
                    else {
                        Logger::warning(conn_id_str() + " 未知消息类型: " +
                                      to_string((int)msg_type));
                        buffer.erase(buffer.begin(), buffer.begin() + 5);
                    }
                }
            }
        } catch (exception& e) {
            if (running) {
                Logger::error(conn_id_str() + " 客户端→游戏转发失败: " +
                            string(e.what()));
            }
            running = false;
        }
    }

    // 线程2：转发游戏服务器→客户端（完全按照Python版本）
    void forward_game_to_client() {
        uint8_t buffer[65536];  // v12.2.0: 增大到64KB，配合流式转发
        const int MAX_RECV_SIZE = 65535;  // v12.3.6: 限制recv大小，防止uint16_t溢出

        Logger::debug(conn_id_str() + " 游戏→客户端转发线程已启动");

        int last_recv_size = 0;
        auto last_recv_time = chrono::system_clock::now();

        try {
            while (running) {
                // **v12.3.6修复: 限制recv大小为65535，防止data_len字段溢出**
                // 协议data_len是uint16_t(2字节)，最大65535
                int n = recv(game_fd, buffer, MAX_RECV_SIZE, 0);

                // ===== 关键诊断点：游戏服务器断开 =====
                if (n <= 0) {
                    auto now = chrono::system_clock::now();
                    auto time_since_last = chrono::duration_cast<chrono::milliseconds>(now - last_recv_time).count();

                    if (n == 0) {
                        Logger::info(conn_id_str() + " [!!!关键!!!] 游戏服务器发送FIN (recv返回0)");
                        Logger::info(conn_id_str() + " 最后一次接收: " + to_string(last_recv_size) +
                                   "字节，距今 " + to_string(time_since_last) + "ms");
                        Logger::info(conn_id_str() + " 执行半关闭：游戏→客户端方向关闭，客户端→游戏方向保持");
                    } else {
                        int err = errno;
                        Logger::error(conn_id_str() + " [!!!关键!!!] 游戏服务器连接错误");
                        Logger::error(conn_id_str() + " recv返回: " + to_string(n) +
                                    ", errno=" + to_string(err) + ": " + strerror(err));
                        Logger::error(conn_id_str() + " 最后一次接收: " + to_string(last_recv_size) +
                                    "字节，距今 " + to_string(time_since_last) + "ms");
                    }

                    // v5.1: 游戏服务器关闭后，完全关闭game_fd防止继续发送数据
                    // 之前的半关闭方案(SHUT_RD)会导致client_to_game继续向已关闭的socket发送数据
                    // 从而在析构时触发sendall(-1)崩溃
                    shutdown(game_fd, SHUT_RDWR);
                    Logger::debug(conn_id_str() + " shutdown游戏socket (SHUT_RDWR)");

                    close(game_fd);
                    int closed_fd = game_fd;
                    game_fd = -1;  // 设置为-1，让client_to_game线程的检查能够发现
                    Logger::info(conn_id_str() + " 已关闭游戏socket fd=" + to_string(closed_fd) +
                               "，client_to_game线程将在下次发送时检测到并停止");

                    // v5.2: 设置running=false，确保连接能够被正确清理
                    // 这是修复频道重选bug的关键：没有这行代码，handle_client()的while循环永远不会退出
                    running = false;
                    Logger::info(conn_id_str() + " 已设置running=false，连接将被清理");

                    break;  // 退出game_to_client线程
                }

                // 记录接收时间和大小
                last_recv_time = chrono::system_clock::now();
                last_recv_size = n;

                // **v12.3.6修复: 防止uint16_t溢出**
                // 协议data_len字段是uint16_t(2字节)，最大值65535
                // 但buffer大小是65536，recv可能返回65536导致溢出为0！
                if (n > 65535) {
                    Logger::warning(conn_id_str() + " ⚠ recv返回" + to_string(n) +
                                  "字节，超过uint16_t最大值65535，需要分包发送");
                    // 先发送65535字节
                    int first_part = 65535;
                    int second_part = n - 65535;

                    // 发送第一部分
                    uint8_t response1[65535 + 7];
                    memset(response1, 0, sizeof(response1));
                    response1[0] = 0x01;
                    *(uint32_t*)(response1 + 1) = htonl(conn_id);
                    *(uint16_t*)(response1 + 5) = htons(first_part);
                    memcpy(response1 + 7, buffer, first_part);

                    if (!sendall(client_fd, response1, 7 + first_part)) {
                        Logger::error(conn_id_str() + " 发送第一部分失败");
                        running = false;
                        break;
                    }
                    Logger::debug(conn_id_str() + " 已发送第一部分: 65535字节");

                    // 发送第二部分
                    uint8_t response2[second_part + 7];
                    memset(response2, 0, sizeof(response2));
                    response2[0] = 0x01;
                    *(uint32_t*)(response2 + 1) = htonl(conn_id);
                    *(uint16_t*)(response2 + 5) = htons(second_part);
                    memcpy(response2 + 7, buffer + first_part, second_part);

                    if (!sendall(client_fd, response2, 7 + second_part)) {
                        Logger::error(conn_id_str() + " 发送第二部分失败");
                        running = false;
                        break;
                    }
                    Logger::debug(conn_id_str() + " 已发送第二部分: " + to_string(second_part) + "字节");

                    continue;  // 跳过后面的正常发送流程
                }

                Logger::debug(conn_id_str() + " [CHECKPOINT-1] 准备打印hex preview, n=" + to_string(n));

                // 打印载荷预览（前16字节）
                string hex_preview = "";
                for (int i = 0; i < min(16, n); i++) {
                    char buf[4];
                    sprintf(buf, "%02x ", buffer[i]);
                    hex_preview += buf;
                }

                Logger::debug(conn_id_str() + " [CHECKPOINT-2] hex preview生成完毕");

                Logger::debug(conn_id_str() + " 从游戏收到 " + to_string(n) +
                            "字节 载荷:" + hex_preview);

                // v5.0: TCP payload IP替换（代理IP → 客户端IP）
                // 游戏服务器返回的数据中如果包含代理IP,需要替换回客户端真实IP
                // 动态获取客户端真实IP（可能在UDP tunnel之后才可用）
                string real_ip = get_client_real_ip();
                if (!real_ip.empty() && !proxy_local_ip.empty()) {
                    int replaced = replace_ip_in_payload(
                        buffer,
                        n,
                        proxy_local_ip,
                        real_ip,
                        conn_id,
                        session_uuid
                    );
                    if (replaced > 0) {
                        Logger::debug(conn_id_str() + " TCP已替换IP: " +
                                    proxy_local_ip + " -> " + real_ip +
                                    " (替换" + to_string(replaced) + "处)");
                    }
                }

                Logger::debug(conn_id_str() + " [CHECKPOINT-3] 准备封装协议, n=" + to_string(n) +
                            ", client_fd=" + to_string(client_fd) + ", running=" + (running ? "true" : "false"));

                // **v3.5.5: 关键修复 - 在发送前检查running状态**
                // 如果client_to_game线程已经设置running=false,说明客户端已断开
                // 此时client_fd可能已被析构函数关闭,不能再调用sendall()
                if (!running) {
                    Logger::info(conn_id_str() + " [!!!修复v3.5.5!!!] 检测到running=false,客户端已断开,跳过sendall()避免崩溃");
                    break;
                }

                // 封装协议：msg_type(1) + conn_id(4) + data_len(2) + payload
                uint8_t response[65536 + 7];  // v12.2.0: 配合更大的缓冲区

                // **v12.3.6修复: 清零response数组，防止栈上垃圾数据被发送**
                // 问题：response是栈上未初始化数组，残留数据可能导致客户端解析错误
                memset(response, 0, 7 + n);  // 只清零需要发送的部分，提高效率

                response[0] = 0x01;
                *(uint32_t*)(response + 1) = htonl(conn_id);
                *(uint16_t*)(response + 5) = htons(n);
                if (n > 0) {
                    memcpy(response + 7, buffer, n);
                }

                // **v12.3.6: 添加诊断日志，检测异常的n值**
                // 注意：n=0的情况已经在前面的 if (n <= 0) 中处理了，这里不会到达
                if (n > 60000 && n <= 65535) {
                    Logger::debug(conn_id_str() + " 大数据包: " + to_string(n) + "字节");
                }

                Logger::debug(conn_id_str() + " [CHECKPOINT-4] 协议封装完成,准备调用sendall(), 总大小=" +
                            to_string(7 + n));

                // sendall - 确保完全发送
                if (!sendall(client_fd, response, 7 + n)) {
                    int err = errno;
                    Logger::error(conn_id_str() + " 发送到客户端失败 (errno=" +
                                to_string(err) + ": " + strerror(err) + ")");
                    running = false;
                    break;
                }

                Logger::debug(conn_id_str() + " [CHECKPOINT-5] sendall()成功返回");

                Logger::debug(conn_id_str() + " 游戏→客户端: 已转发 " +
                            to_string(n) + "字节");
            }

            Logger::debug(conn_id_str() + " 游戏→客户端转发线程正常退出");

        } catch (exception& e) {
            if (running) {
                Logger::error(conn_id_str() + " 游戏→客户端转发异常: " +
                            string(e.what()));
            }
            running = false;
        }
    }

    // UDP转发到游戏服务器
    void forward_udp_to_game(uint16_t src_port, uint16_t dst_port, const vector<uint8_t>& data) {
        try {
            lock_guard<mutex> lock(udp_mutex);

            // 获取或创建UDP socket
            if (udp_sockets.find(dst_port) == udp_sockets.end()) {
                // 使用getaddrinfo解析游戏服务器地址
                struct addrinfo hints{}, *result = nullptr;
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = IPPROTO_UDP;

                string port_str = to_string(dst_port);
                int ret = getaddrinfo(game_server_ip.c_str(), port_str.c_str(), &hints, &result);
                if (ret != 0 || result == nullptr) {
                    Logger::error(conn_id_str() + "|UDP:" + to_string(dst_port) +
                                " DNS解析失败: " + game_server_ip);
                    return;
                }

                int udp_fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
                freeaddrinfo(result);

                if (udp_fd < 0) {
                    Logger::error(conn_id_str() + "|UDP:" + to_string(dst_port) +
                                " 创建UDP socket失败");
                    return;
                }
                udp_sockets[dst_port] = udp_fd;

                Logger::info(conn_id_str() + "|UDP:" + to_string(dst_port) +
                           " 创建UDP socket");

                // 启动UDP接收线程 - **关键修复**: 必须捕获shared_from_this()防止Use-After-Free
                // UDP线程也需要持有shared_ptr引用,否则对象可能在线程运行时被销毁
                auto self = shared_from_this();
                auto t = make_shared<thread>([self, dst_port, src_port]() {
                    self->recv_udp_from_game(dst_port, src_port);
                });
                udp_threads[dst_port] = t;
            }

            // 发送到游戏服务器 - 使用getaddrinfo解析地址
            int udp_fd = udp_sockets[dst_port];

            struct addrinfo hints{}, *result = nullptr;
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;

            string port_str = to_string(dst_port);
            int ret = getaddrinfo(game_server_ip.c_str(), port_str.c_str(), &hints, &result);
            if (ret != 0 || result == nullptr) {
                Logger::error(conn_id_str() + "|UDP:" + to_string(dst_port) +
                            " DNS解析失败");
                return;
            }

            sendto(udp_fd, data.data(), data.size(), 0, result->ai_addr, result->ai_addrlen);
            freeaddrinfo(result);

            Logger::debug(conn_id_str() + "|UDP:" + to_string(dst_port) +
                        " 客户端→游戏: " + to_string(data.size()) + "字节");

        } catch (exception& e) {
            Logger::error(conn_id_str() + "|UDP:" + to_string(dst_port) +
                        " 转发失败: " + string(e.what()));
        }
    }

    // UDP从游戏服务器接收
    void recv_udp_from_game(int dst_port, int client_port) {
        try {
            int udp_fd;
            {
                lock_guard<mutex> lock(udp_mutex);
                if (udp_sockets.find(dst_port) == udp_sockets.end())
                    return;
                udp_fd = udp_sockets[dst_port];
            }

            uint8_t buffer[65535];
            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);

            while (running) {
                int n = recvfrom(udp_fd, buffer, sizeof(buffer), 0,
                               (sockaddr*)&from_addr, &from_len);
                if (n <= 0) break;

                // 封装协议：msg_type(1) + conn_id(4) + src_port(2) + dst_port(2) + data_len(2) + payload
                uint8_t response[65535 + 11];
                response[0] = 0x03;
                *(uint32_t*)(response + 1) = htonl(conn_id);
                *(uint16_t*)(response + 5) = htons(dst_port);      // src_port（游戏服务器）
                *(uint16_t*)(response + 7) = htons(client_port);   // dst_port（游戏客户端）
                *(uint16_t*)(response + 9) = htons(n);            // data_len
                memcpy(response + 11, buffer, n);

                // sendall
                if (!sendall(client_fd, response, 11 + n)) {
                    Logger::error(conn_id_str() + "|UDP:" + to_string(dst_port) +
                                " 发送失败");
                    break;
                }

                Logger::debug(conn_id_str() + "|UDP:" + to_string(dst_port) +
                            " 游戏→客户端: " + to_string(n) + "字节");
            }
        } catch (exception& e) {
            Logger::error(conn_id_str() + "|UDP 接收线程异常: " +
                        string(e.what()));
        }
    }
};

// ==================== 隧道服务器 ====================
class TunnelServer : public enable_shared_from_this<TunnelServer> {
private:
    ServerConfig config;
    string server_name;
    int listen_fd;
    map<string, shared_ptr<TunnelConnection>> connections;  // key: "client_addr:conn_id" - 使用智能指针
    mutex conn_mutex;
    atomic<bool> running;

    // v5.0: 存储TCP连接源IP到客户端真实IPv4的映射
    map<string, string> client_ip_map;  // TCP源IP(不含端口) -> 客户端真实IPv4
    mutex ip_map_mutex;

    // v5.0: 从client_str中提取TCP源IP（不含端口）
    // 输入: "[::ffff:192.168.2.1]:56601" 或 "[240e:...]:12345"
    // 输出: "192.168.2.1" 或 "240e:..."
    string extract_tcp_source_ip(const string& client_str) {
        size_t start = client_str.find('[');
        size_t end = client_str.find(']');
        if (start == string::npos || end == string::npos || end <= start) {
            return "";  // 格式错误
        }

        string ip_part = client_str.substr(start + 1, end - start - 1);  // 提取[...]中的内容

        // 检查是否为IPv4映射IPv6格式: ::ffff:x.x.x.x
        const string ipv4_prefix = "::ffff:";
        if (ip_part.find(ipv4_prefix) == 0) {
            return ip_part.substr(ipv4_prefix.length());  // 返回IPv4部分
        }

        return ip_part;  // 返回完整IP（IPv6或其他格式）
    }

public:
    TunnelServer(const ServerConfig& cfg)
        : config(cfg), server_name(cfg.name), listen_fd(-1), running(false) {}

    ~TunnelServer() {
        stop();
        // 智能指针自动释放，无需手动delete
        connections.clear();
    }

    bool start() {
        // 创建IPv6 socket（支持双栈：同时接受IPv4和IPv6连接）
        listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            Logger::error("[" + server_name + "] 创建socket失败");
            return false;
        }

        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        // 设置双栈模式：IPV6_V6ONLY=0 允许接受IPv4连接
        int v6only = 0;
        if (setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0) {
            Logger::warning("[" + server_name + "] 设置双栈模式失败，将只支持IPv6");
        } else {
            Logger::debug("[" + server_name + "] 已启用IPv4/IPv6双栈模式");
        }

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;  // 监听所有IPv6地址（双栈模式下也监听IPv4）
        addr.sin6_port = htons(config.listen_port);

        if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
            Logger::error("[" + server_name + "] 绑定端口失败: " + to_string(config.listen_port));
            close(listen_fd);
            return false;
        }

        if (listen(listen_fd, config.max_connections) < 0) {
            Logger::error("[" + server_name + "] 监听失败");
            close(listen_fd);
            return false;
        }

        running = true;
        Logger::info("[" + server_name + "] 服务器启动成功，监听端口: " + to_string(config.listen_port) + " (IPv4/IPv6双栈)");
        Logger::info("[" + server_name + "] 游戏服务器: " + config.game_server_ip);

        accept_loop();
        return true;
    }

    void stop() {
        running = false;
        if (listen_fd >= 0) {
            close(listen_fd);
            listen_fd = -1;
        }
    }

    bool is_running() const {
        return running;
    }

private:
    void accept_loop() {
        while (running) {
            sockaddr_storage client_addr{};  // 使用sockaddr_storage支持IPv4/IPv6
            socklen_t addr_len = sizeof(client_addr);

            int client_fd = accept(listen_fd, (sockaddr*)&client_addr, &addr_len);
            if (client_fd < 0) {
                if (running) {
                    Logger::error("接受连接失败");
                }
                continue;
            }

            // 提取客户端IP地址（支持IPv4和IPv6）
            char client_ip[INET6_ADDRSTRLEN];
            int client_port = 0;
            string client_str;

            if (client_addr.ss_family == AF_INET) {
                // IPv4客户端
                sockaddr_in* addr_in = (sockaddr_in*)&client_addr;
                inet_ntop(AF_INET, &addr_in->sin_addr, client_ip, INET6_ADDRSTRLEN);
                client_port = ntohs(addr_in->sin_port);
                client_str = string(client_ip) + ":" + to_string(client_port);
            } else if (client_addr.ss_family == AF_INET6) {
                // IPv6客户端
                sockaddr_in6* addr_in6 = (sockaddr_in6*)&client_addr;
                inet_ntop(AF_INET6, &addr_in6->sin6_addr, client_ip, INET6_ADDRSTRLEN);
                client_port = ntohs(addr_in6->sin6_port);
                client_str = "[" + string(client_ip) + "]:" + to_string(client_port);
            } else {
                client_str = "unknown";
            }

            Logger::info("新客户端连接: " + client_str);

            // 在新线程中处理客户端 - 使用shared_from_this()避免Use-After-Free
            auto self = shared_from_this();
            thread([self, client_fd, client_str]() {
                self->handle_client(client_fd, client_str);
            }).detach();
        }
    }

    void handle_client(int client_fd, const string& client_str) {
        try {
            // v4.5.0: 用于存储从UDP握手payload中解析的客户端IP
            string client_ipv4 = "";

            // 接收握手：conn_id(4) + dst_port(2) + session_uuid_len(1) + session_uuid(N)
            uint8_t handshake[7];
            int n = recv(client_fd, handshake, 7, MSG_WAITALL);

            if (n != 7) {
                Logger::error("客户端 " + client_str + " 握手失败 (recv=" + to_string(n) + ", 期望7字节)");
                close(client_fd);
                return;
            }

            // ===== 调试日志:打印原始握手数据 =====
            char hex_buf[100];
            sprintf(hex_buf, "%02x %02x %02x %02x %02x %02x %02x",
                    handshake[0], handshake[1], handshake[2],
                    handshake[3], handshake[4], handshake[5], handshake[6]);
            Logger::debug("[握手] 收到握手数据(hex): " + string(hex_buf));

            uint32_t conn_id = ntohl(*(uint32_t*)handshake);
            uint16_t dst_port = ntohs(*(uint16_t*)(handshake + 4));
            uint8_t session_uuid_len = handshake[6];

            // 接收session UUID
            string session_uuid = "";
            if (session_uuid_len > 0 && session_uuid_len < 255) {
                vector<char> uuid_buf(session_uuid_len + 1, 0);
                int uuid_recv = recv(client_fd, uuid_buf.data(), session_uuid_len, MSG_WAITALL);
                if (uuid_recv == (int)session_uuid_len) {
                    session_uuid = string(uuid_buf.data(), session_uuid_len);
                } else {
                    Logger::warning("[握手] 接收会话UUID失败 (期望" + to_string(session_uuid_len) +
                                  "字节, 收到" + to_string(uuid_recv) + "字节)");
                }
            }

            char conn_id_hex[20];
            sprintf(conn_id_hex, "0x%08x", conn_id);
            Logger::debug("[握手] 解析结果: conn_id=" + to_string(conn_id) +
                        " (" + string(conn_id_hex) + "), dst_port=" + to_string(dst_port) +
                        ", session_uuid=" + session_uuid);

            // ===== 关键修改：识别UDP tunnel连接 =====
            const uint32_t UDP_MAGIC = 0xFFFFFFFF;

            Logger::debug("[握手] 判断UDP Tunnel: conn_id=" + to_string(conn_id) +
                        ", UDP_MAGIC=" + to_string(UDP_MAGIC) +
                        ", 相等?" + (conn_id == UDP_MAGIC ? "YES" : "NO"));

            if (conn_id == UDP_MAGIC) {
                Logger::info("[UDP Tunnel|" + session_uuid + "] ✓ 识别为UDP Tunnel连接!");
                Logger::info("[UDP Tunnel|" + session_uuid + "] 收到UDP握手请求(第一部分): 客户端=" + client_str +
                           ", 游戏端口=" + to_string(dst_port));

                // ===== 新协议: 接收客户端IPv4地址(4字节) =====
                uint8_t ipv4_bytes[4];
                int ip_received = recv(client_fd, ipv4_bytes, 4, MSG_WAITALL);
                if (ip_received != 4) {
                    Logger::error("[UDP Tunnel|" + session_uuid + "] 握手失败: 未接收到客户端IPv4地址 (received=" +
                                to_string(ip_received) + ")");
                    close(client_fd);
                    return;
                }

                // 将IPv4字节转换为字符串
                char ipv4_str[INET_ADDRSTRLEN];
                struct in_addr ipv4_addr;
                memcpy(&ipv4_addr, ipv4_bytes, 4);
                inet_ntop(AF_INET, &ipv4_addr, ipv4_str, INET_ADDRSTRLEN);
                client_ipv4 = string(ipv4_str);  // v4.5.0: 赋值给外层变量,不重新声明

                Logger::info("[UDP Tunnel|" + session_uuid + "] 收到客户端IPv4地址(payload中): " + client_ipv4);

                // v5.0: 存储TCP源IP到客户端真实IPv4的映射
                string tcp_source_ip = extract_tcp_source_ip(client_str);
                if (!tcp_source_ip.empty() && !client_ipv4.empty()) {
                    lock_guard<mutex> lock(ip_map_mutex);
                    client_ip_map[tcp_source_ip] = client_ipv4;
                    Logger::info("[UDP Tunnel|" + session_uuid + "] v5.0存储IP映射: TCP源IP=" + tcp_source_ip +
                               " -> 客户端真实IPv4=" + client_ipv4);
                }

                // 发送UDP握手确认响应(与TCP握手相同的6字节格式)
                uint8_t ack[6];
                *(uint32_t*)ack = htonl(0xFFFFFFFF);  // conn_id=0xFFFFFFFF表示握手确认
                *(uint16_t*)(ack + 4) = htons(dst_port);  // 回传端口

                if (send(client_fd, ack, 6, 0) != 6) {
                    Logger::error("[UDP Tunnel|" + session_uuid + "] 发送握手确认失败");
                    close(client_fd);
                    return;
                }

                Logger::info("[UDP Tunnel|" + session_uuid + "] 握手成功,已发送确认");
                Logger::info("[UDP Tunnel|" + session_uuid + "] 调用 handle_udp_tunnel()");
                // v4.5.0: 传递TCP真实IP(client_str)和payload中的IP(client_ipv4)
                handle_udp_tunnel(client_fd, client_str, client_ipv4, dst_port, session_uuid);
                Logger::info("[UDP Tunnel|" + session_uuid + "] handle_udp_tunnel()函数已返回");
                return;
            }

            Logger::debug("[握手] ✗ 不是UDP Tunnel,按普通TCP连接处理");
            Logger::info("[连接" + to_string(conn_id) + "|" + session_uuid + "] 握手成功: 目标端口=" +
                        to_string(dst_port) + ", 客户端=" + client_str);

            // v5.0: 从映射中查询客户端真实IPv4
            string tcp_source_ip = extract_tcp_source_ip(client_str);
            string client_real_ipv4 = "";
            {
                lock_guard<mutex> lock(ip_map_mutex);
                auto it = client_ip_map.find(tcp_source_ip);
                if (it != client_ip_map.end()) {
                    client_real_ipv4 = it->second;
                }
            }

            // v5.0: 计算代理服务器本地IP(用于连接游戏服务器的本地IP)
            string proxy_local_ip = get_local_ip(config.game_server_ip);

            Logger::debug("[连接" + to_string(conn_id) + "|" + session_uuid + "] v5.0 IP替换准备: TCP源IP=" + tcp_source_ip +
                        ", 客户端真实IPv4=" + client_real_ipv4 + ", 代理IP=" + proxy_local_ip);

            // 创建连接对象 - 使用智能指针
            // v5.0: 传递IP参数以支持TCP payload IP替换
            // client_real_ipv4可能为空（TCP连接在UDP tunnel之前建立）
            // 传递tcp_source_ip和映射指针，支持动态查询
            auto conn = make_shared<TunnelConnection>(
                conn_id, client_fd, config.game_server_ip, dst_port,
                client_real_ipv4,  // client_real_ip (可能为空)
                proxy_local_ip,    // proxy_ip
                tcp_source_ip,     // tcp_source_ip (用于动态查询)
                &client_ip_map,    // IP映射指针
                &ip_map_mutex,     // 映射互斥锁指针
                session_uuid       // 会话UUID
            );

            string conn_key = client_str + ":" + to_string(conn_id);
            {
                lock_guard<mutex> lock(conn_mutex);
                connections[conn_key] = conn;
            }

            // 启动连接（启动双向转发线程）
            if (!conn->start()) {
                lock_guard<mutex> lock(conn_mutex);
                connections.erase(conn_key);
                // 智能指针自动释放，无需delete
                return;
            }

            // v12.3.15修复: 移除300秒硬超时，改用无限期等待 + TCP keepalive/心跳机制检测真正断线
            // 原bug: 无论玩家是否活跃，300秒后强制关闭，导致正常游戏被断开连接
            // 新策略:
            //   1. 不设硬性时间限制，依靠协议自然结束
            //   2. TCP keepalive会自动检测网络断开
            //   3. 游戏/客户端主动关闭会触发FIN，自然结束连接
            //   4. 僵尸连接由操作系统TCP层的keepalive机制处理
            while (conn->is_running()) {
                this_thread::sleep_for(chrono::seconds(1));
            }

            Logger::info("[连接" + to_string(conn_id) + "|" + session_uuid + "] 连接已结束，开始清理资源");

            // 清理 - 关键修复: 在mutex保护下擦除，智能指针自动管理内存
            {
                lock_guard<mutex> lock(conn_mutex);
                connections.erase(conn_key);
            }
            Logger::info("[连接" + to_string(conn_id) + "|" + session_uuid + "] 连接已从映射中移除，资源已释放");
            // 智能指针自动释放，无需delete - 修复了原来第992行的race condition!

        } catch (exception& e) {
            Logger::error("处理客户端 " + client_str + " 时出错: " + string(e.what()));
            close(client_fd);
        }
    }

    // 处理UDP tunnel连接
    // v4.5.0: 添加client_ipv4_from_payload参数,包含客户端payload中声明的IP
    void handle_udp_tunnel(int client_fd, const string& client_str,
                          const string& client_ipv4_from_payload, uint16_t game_port,
                          const string& session_uuid = "") {
        try {
            // 提取客户端真实IP地址(TCP连接源IP,客户端公网IP)
            string real_client_ip;

            // 处理IPv6格式: [xxxx]:port 或 IPv4格式: x.x.x.x:port
            if (client_str.front() == '[') {
                // IPv6格式: [xxxx]:port
                // 找到最后一个']'的位置
                size_t bracket_end = client_str.find(']');
                if (bracket_end != string::npos) {
                    // 提取方括号内的内容
                    string ip_with_brackets = client_str.substr(0, bracket_end + 1);
                    // 去掉方括号
                    real_client_ip = ip_with_brackets.substr(1, ip_with_brackets.length() - 2);

                    // 检查是否是IPv6映射的IPv4地址 (::ffff:x.x.x.x)
                    if (real_client_ip.find("::ffff:") == 0) {
                        // 提取IPv4部分
                        real_client_ip = real_client_ip.substr(7);  // 去掉"::ffff:"前缀
                    }
                } else {
                    // 格式错误,使用整个字符串
                    real_client_ip = client_str;
                }
            } else {
                // 纯IPv4格式: x.x.x.x:port
                size_t colon_pos = client_str.find(":");
                if (colon_pos != string::npos) {
                    real_client_ip = client_str.substr(0, colon_pos);
                } else {
                    real_client_ip = client_str;
                }
            }

            // v4.5.0: 使用传入的payload IP
            string client_ipv4 = client_ipv4_from_payload;

            string uuid_prefix = session_uuid.empty() ? "[UDP Tunnel]" : "[UDP Tunnel|" + session_uuid + "]";

            Logger::info(uuid_prefix + " 开始处理UDP代理连接");
            Logger::info(uuid_prefix + " 客户端字符串: " + client_str);
            Logger::info(uuid_prefix + " 客户端公网IP(TCP源): " + real_client_ip);
            Logger::info(uuid_prefix + " 客户端私网IP(payload): " + client_ipv4);

            // ===== v4.5.0关键: 获取代理服务器本地IP =====
            string proxy_local_ip = get_local_ip(config.game_server_ip);
            if (proxy_local_ip.empty()) {
                Logger::error(uuid_prefix + " 无法获取代理服务器本地IP,使用默认值");
                proxy_local_ip = "192.168.2.75";  // 回退默认值
            }
            Logger::info(uuid_prefix + " 代理服务器本地IP: " + proxy_local_ip);
            Logger::info(uuid_prefix + " v5.0策略: 客户端→服务器(客户端IP→代理IP), 服务器→客户端(代理IP→客户端IP)");

            // **关键修复v3.5**: 使用shared_ptr包装本地变量,防止线程持有悬垂引用
            // v4.7.0重构: 按源端口管理UDP socket - 每个客户端源端口一个socket
            // v5.1修复: 支持多用户 - 按(client_str, src_port)管理socket
            // 原因: 多个客户端可能使用相同源端口(如5063),需要区分
            auto udp_sockets = make_shared<map<string, int>>();  // ["client_str:src_port"] = socket
            auto udp_recv_threads = make_shared<map<string, shared_ptr<thread>>>();  // ["client_str:src_port"] = thread

            // v4.7.0: 存储每个数据流(src_port, dst_port)的元数据
            // v5.1修复: key改为"client_str:src_port:dst_port"支持多用户
            struct FlowMetadata {
                uint32_t conn_id;
                uint16_t src_port;          // 客户端源端口
                uint16_t dst_port;          // 游戏服务器目标端口
                string client_public_ip;    // 客户端公网IP (TCP源IP)
                string client_private_ip;   // 客户端私网IP (payload中)
            };
            // v5.1: 使用 "client_str:src_port:dst_port" 作为key
            auto flow_metadata = make_shared<map<string, FlowMetadata>>();
            auto udp_mutex = make_shared<mutex>();
            auto send_mutex = make_shared<mutex>();  // 保护client_fd的send操作,防止多线程竞争
            auto running = make_shared<atomic<bool>>(true);

            // v4.5.0: 捕获proxy_local_ip用于IP替换（已废弃）
            string proxy_ip_for_lambda = proxy_local_ip;  // Lambda捕获用

            // 创建UDP接收线程的lambda函数 - 返回智能指针
            // **关键修复v3.5**: 捕获shared_ptr而不是引用,确保变量生命周期正确
            // v4.5.0: 新增proxy_ip_for_lambda用于IP替换（已废弃）
            // v4.7.0重构: 参数改为src_port，一个线程处理该源端口的所有流量
            // v4.7.3: 移除game_server_ip_for_lambda，改用client_public_ip（从flow_metadata获取）
            // v5.1修复: 参数改为socket_key="client_str:src_port"支持多用户
            auto create_udp_receiver = [udp_sockets, flow_metadata, udp_mutex, send_mutex, running, proxy_ip_for_lambda](const string& socket_key, uint16_t src_port, int client_fd) -> shared_ptr<thread> {
                return make_shared<thread>([udp_sockets, flow_metadata, udp_mutex, send_mutex, running, proxy_ip_for_lambda, socket_key, src_port, client_fd]() {
                    try {
                        int udp_fd;
                        {
                            lock_guard<mutex> lock(*udp_mutex);
                            if (udp_sockets->find(socket_key) == udp_sockets->end()) {
                                Logger::error("[UDP Tunnel|" + socket_key + "] socket不存在");
                                return;
                            }
                            udp_fd = (*udp_sockets)[socket_key];
                        }

                        uint8_t buffer[65535];
                        sockaddr_storage from_addr{};
                        socklen_t from_len = sizeof(from_addr);

                        Logger::info("[UDP Tunnel|" + socket_key + "] 接收线程已启动");

                        while (*running) {
                            Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "] 等待从游戏服务器接收UDP数据...");

                            from_len = sizeof(from_addr);
                            int n = recvfrom(udp_fd, buffer, sizeof(buffer), 0,
                                           (sockaddr*)&from_addr, &from_len);

                            if (n <= 0) {
                                int err = errno;
                                Logger::info("[UDP Tunnel|src=" + to_string(src_port) +
                                           "] recvfrom返回: n=" + to_string(n) +
                                           ", errno=" + to_string(err) + " (" + strerror(err) + ")");
                                break;
                            }

                            // v4.7.0: 获取游戏服务器的端口（响应来自哪个目标端口）
                            uint16_t game_server_port = 0;
                            if (from_addr.ss_family == AF_INET) {
                                sockaddr_in* addr_in = (sockaddr_in*)&from_addr;
                                game_server_port = ntohs(addr_in->sin_port);
                            } else if (from_addr.ss_family == AF_INET6) {
                                sockaddr_in6* addr_in6 = (sockaddr_in6*)&from_addr;
                                game_server_port = ntohs(addr_in6->sin6_port);
                            }

                            Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                        "] ←[游戏服务器] 接收到UDP数据: " + to_string(n) + "字节");

                            // v4.7.0: 根据(src_port, game_server_port)查找流元数据
                            // v5.1修复: flow_key改为"socket_key:dst_port"支持多用户
                            uint32_t conn_id = 0;
                            uint16_t client_port = src_port;
                            string client_public_ip = "";
                            string client_private_ip = "";

                            {
                                lock_guard<mutex> lock(*udp_mutex);
                                string flow_key = socket_key + ":" + to_string(game_server_port);
                                auto flow_it = flow_metadata->find(flow_key);
                                if (flow_it != flow_metadata->end()) {
                                    conn_id = flow_it->second.conn_id;
                                    client_port = flow_it->second.src_port;
                                    client_public_ip = flow_it->second.client_public_ip;
                                    client_private_ip = flow_it->second.client_private_ip;
                                } else {
                                    Logger::warning("[UDP Tunnel|" + socket_key + "|dst=" +
                                                  to_string(game_server_port) + "] 未找到流元数据，可能是延迟响应");
                                    continue;
                                }
                            }

                            // 打印接收到的UDP payload hex dump
                            string payload_hex = "";
                            for (int i = 0; i < n; i++) {
                                if (i > 0 && i % 16 == 0) {
                                    payload_hex += "\n                    ";
                                }
                                char hex_buf[4];
                                sprintf(hex_buf, "%02x ", buffer[i]);
                                payload_hex += hex_buf;
                            }
                            Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                        "] UDP Payload(" + to_string(n) + "字节):\n                    " + payload_hex);

                            // ===== v4.9.1关键修复: UDP握手响应 - 替换IP字段和端口字段 =====
                            // 算法发现: 通过多次抓包分析确认
                            //          IP字段 = UDP包的源IP
                            //          最后2字节 = UDP包的源端口（小端序）
                            //          游戏服务器完全基于收到的UDP包源地址计算响应
                            // 异地代理问题:
                            //          代理用自己的IP:Port发送UDP包到游戏服务器
                            //          服务器返回基于代理IP:Port的响应
                            //          但客户端期望看到基于自己IP:Port的响应
                            // 解决方案: 同时替换IP字段和端口字段为客户端真实值
                            if (n >= 7 && buffer[0] == 0x02) {
                                // 握手响应格式: 02 + IP(4字节,DNF字节序) + Port(2字节,小端序)

                                // 读取服务器返回的IP字段（DNF字节序 [d,c,b,a] 表示 a.b.c.d）
                                char server_ip_str[20];
                                sprintf(server_ip_str, "%d.%d.%d.%d", buffer[4], buffer[3], buffer[2], buffer[1]);

                                // 读取服务器返回的端口字段（小端序）
                                uint16_t server_port_le = ((uint16_t)buffer[6] << 8) | buffer[5];

                                Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                           "] 检测到UDP握手响应，服务器返回: IP=" + string(server_ip_str) +
                                           ", Port=" + to_string(server_port_le) + " (0x" +
                                           [](uint16_t v){ char buf[8]; sprintf(buf, "%04x", v); return string(buf); }(server_port_le) + ")");

                                // v5.0关键修复: 替换为客户端真实IP（从payload提取）
                                // 原因: 游戏客户端期望UDP握手响应IP = 自己的真实IP（payload中的IP）
                                //      代理发送时已将payload中的IP替换为代理IP
                                //      游戏服务器返回基于代理IP的响应
                                //      必须还原为客户端真实IP让客户端验证通过
                                if (!client_private_ip.empty()) {
                                    unsigned int a, b, c, d;
                                    if (sscanf(client_private_ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                                        Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                                   "] 替换为客户端真实IP: " + client_private_ip + ", Port=" + to_string(client_port));

                                        // 替换IP字段（DNF字节序 [d,c,b,a]）
                                        buffer[1] = (uint8_t)d;
                                        buffer[2] = (uint8_t)c;
                                        buffer[3] = (uint8_t)b;
                                        buffer[4] = (uint8_t)a;

                                        // 替换端口字段（小端序 [low, high]）
                                        buffer[5] = (uint8_t)(client_port & 0xFF);         // 低字节
                                        buffer[6] = (uint8_t)((client_port >> 8) & 0xFF);  // 高字节

                                        Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                                   "] ✓ 已替换IP字段和端口字段");

                                        // 打印替换后的payload
                                        char new_hex[50];
                                        sprintf(new_hex, "%02x %02x %02x %02x %02x %02x %02x",
                                               buffer[0], buffer[1], buffer[2], buffer[3],
                                               buffer[4], buffer[5], buffer[6]);
                                        Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                                   "] 替换后payload: " + string(new_hex));
                                    } else {
                                        Logger::warning("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                                      "] 客户端IP格式错误: " + client_private_ip);
                                    }
                                } else {
                                    Logger::warning("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                                  "] 客户端真实IP为空，无法替换");
                                }
                            }

                            // 封装协议：msg_type(1) + conn_id(4) + src_port(2) + dst_port(2) + data_len(2) + payload
                            vector<uint8_t> response(11 + n);
                            response[0] = 0x03;  // msg_type=UDP
                            *(uint32_t*)(&response[1]) = htonl(conn_id);
                            *(uint16_t*)(&response[5]) = htons(game_server_port);   // src_port=游戏服务器端口
                            *(uint16_t*)(&response[7]) = htons(client_port);        // dst_port=客户端端口
                            *(uint16_t*)(&response[9]) = htons(n);
                            memcpy(&response[11], buffer, n);

                            // 打印封装后的完整response数据包
                            string response_hex = "";
                            int dump_len = min(28, (int)response.size());  // 打印前28字节(协议头11+部分payload)
                            for (int i = 0; i < dump_len; i++) {
                                if (i > 0 && i % 16 == 0) {
                                    response_hex += "\n                    ";
                                }
                                char hex_buf[4];
                                sprintf(hex_buf, "%02x ", response[i]);
                                response_hex += hex_buf;
                            }
                            Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                        "] 封装后数据包(前" + to_string(dump_len) + "字节):\n                    " + response_hex);

                            // 发送到客户端 - 使用互斥锁保护,防止多线程同时send()导致数据损坏
                            {
                                lock_guard<mutex> lock(*send_mutex);
                                Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                           "] →[客户端] 准备发送: " + to_string(response.size()) +
                                           "字节 (client_fd=" + to_string(client_fd) +
                                           ", conn_id=" + to_string(conn_id) + ")");

                                int sent = 0;
                                while (sent < (int)response.size() && *running) {
                                    int ret = send(client_fd, response.data() + sent,
                                                 response.size() - sent, 0);

                                    Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                               "] send()返回: " + to_string(ret) +
                                               " (已发送: " + to_string(sent) +
                                               "/" + to_string(response.size()) + "字节)");

                                    if (ret <= 0) {
                                        int err = errno;
                                        Logger::error("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                                    "] send()失败: 返回值=" + to_string(ret) +
                                                    ", errno=" + to_string(err) + " (" + strerror(err) + ")");
                                        *running = false;
                                        break;
                                    }
                                    sent += ret;
                                }

                                if (sent == (int)response.size()) {
                                    Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(game_server_port) +
                                                "] ✓ 成功发送到客户端: " + to_string(response.size()) +
                                                "字节 (conn_id=" + to_string(conn_id) + ")");
                                } else {
                                    Logger::error("[UDP Tunnel|src=" + to_string(src_port) +
                                                "] ✗ 发送不完整: 仅发送 " + to_string(sent) +
                                                "/" + to_string(response.size()) + "字节");
                                }
                            }
                        }

                        Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "] 接收线程退出");
                    } catch (exception& e) {
                        Logger::error("[UDP Tunnel] 接收线程异常: " + string(e.what()));
                    }
                });
            };

            // 主循环：接收客户端的UDP数据
            vector<uint8_t> buffer;
            uint8_t recv_buf[4096];

            Logger::info(uuid_prefix + " 进入UDP转发循环 (client_fd=" + to_string(client_fd) + ")");

            while (*running) {
                Logger::debug(uuid_prefix + " 等待从客户端接收数据...");

                int n = recv(client_fd, recv_buf, sizeof(recv_buf), 0);

                if (n <= 0) {
                    int err = errno;
                    if (n == 0) {
                        Logger::info(uuid_prefix + " 客户端正常断开 (recv返回0)");
                    } else {
                        Logger::error(uuid_prefix + " 客户端连接错误 (recv返回" + to_string(n) +
                                    ", errno=" + to_string(err) + ": " + strerror(err) + ")");
                    }
                    break;
                }

                Logger::info(uuid_prefix + " ←[客户端] 收到 " + to_string(n) + "字节");

                // 添加到缓冲区
                buffer.insert(buffer.end(), recv_buf, recv_buf + n);

                // 解析协议：msg_type(1) + conn_id(4) + src_port(2) + dst_port(2) + data_len(2) + payload
                while (buffer.size() >= 11 && *running) {
                    uint8_t msg_type = buffer[0];
                    uint32_t msg_conn_id = ntohl(*(uint32_t*)&buffer[1]);
                    uint16_t src_port = ntohs(*(uint16_t*)&buffer[5]);
                    uint16_t dst_port = ntohs(*(uint16_t*)&buffer[7]);
                    uint16_t data_len = ntohs(*(uint16_t*)&buffer[9]);

                    // 检查数据是否完整
                    if (buffer.size() < static_cast<size_t>(11 + data_len)) {
                        break;
                    }

                    if (msg_type != 0x03) {
                        Logger::warning("[UDP Tunnel] 未知消息类型: " + to_string((int)msg_type));
                        buffer.erase(buffer.begin(), buffer.begin() + 1);
                        continue;
                    }

                    // 提取payload
                    vector<uint8_t> payload(buffer.begin() + 11, buffer.begin() + 11 + data_len);
                    buffer.erase(buffer.begin(), buffer.begin() + 11 + data_len);

                    Logger::debug("[UDP Tunnel] 解析: conn_id=" + to_string(msg_conn_id) +
                                ", src=" + to_string(src_port) + ", dst=" + to_string(dst_port) +
                                ", len=" + to_string(data_len));

                    // v4.7.0: 按源端口获取或创建UDP socket
                    // v5.1修复: 使用client_str:src_port作为key支持多用户
                    // v5.1: 构造socket_key = "client_str:src_port" (在块外定义，供后续使用)
                    string socket_key = client_str + ":" + to_string(src_port);

                    {
                        lock_guard<mutex> lock(*udp_mutex);

                        // 检查此客户端的源端口是否已有socket
                        if (udp_sockets->find(socket_key) == udp_sockets->end()) {
                            // 首次遇到此源端口，创建socket并bind
                            int udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                            if (udp_fd < 0) {
                                Logger::error("[UDP Tunnel|src=" + to_string(src_port) +
                                            "] 创建UDP socket失败");
                                continue;
                            }

                            // v4.9.0: 普通bind到源端口（不做源IP欺骗）
                            // v5.1修复: bind失败时允许系统自动分配（支持多用户共享端口）
                            // 原因: 多个客户端可能使用相同源端口，第一个成功bind，后续使用自动分配
                            // v5.2修复: bind到proxy_local_ip而不是INADDR_ANY，解决多网卡环境下UDP路由问题
                            struct sockaddr_in local_addr{};
                            local_addr.sin_family = AF_INET;
                            // 使用proxy_local_ip确保UDP包从正确的网卡发出（与游戏服务器同网段）
                            if (inet_pton(AF_INET, proxy_ip_for_lambda.c_str(), &local_addr.sin_addr) != 1) {
                                Logger::warning("[UDP Tunnel|" + socket_key +
                                              "] proxy_local_ip无效(" + proxy_ip_for_lambda +
                                              ")，回退到INADDR_ANY");
                                local_addr.sin_addr.s_addr = INADDR_ANY;
                            }
                            local_addr.sin_port = htons(src_port);

                            bool bind_success = true;
                            if (bind(udp_fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
                                int bind_err = errno;
                                if (bind_err == EADDRINUSE) {
                                    // v5.1: 端口被占用（多用户场景），允许系统自动分配
                                    Logger::info("[UDP Tunnel|" + socket_key +
                                                "] 端口" + to_string(src_port) + "已被占用，使用系统自动分配");
                                    bind_success = false;  // 不bind，系统会自动分配端口
                                } else {
                                    Logger::error("[UDP Tunnel|" + socket_key +
                                                "] bind失败: " + strerror(bind_err));
                                    close(udp_fd);
                                    continue;
                                }
                            }

                            (*udp_sockets)[socket_key] = udp_fd;
                            if (bind_success) {
                                Logger::info("[UDP Tunnel|" + socket_key +
                                           "] ✓ 创建UDP socket并bind到 " + proxy_ip_for_lambda +
                                           ":" + to_string(src_port));
                            } else {
                                Logger::info("[UDP Tunnel|" + socket_key +
                                           "] ✓ 创建UDP socket（系统自动分配端口）");
                            }

                            // 启动接收线程（每个客户端的源端口一个线程）
                            auto t = create_udp_receiver(socket_key, src_port, client_fd);
                            (*udp_recv_threads)[socket_key] = t;
                            Logger::info("[UDP Tunnel|" + socket_key + "] 接收线程已启动");
                        } else {
                            Logger::debug("[UDP Tunnel|" + socket_key + "] UDP socket已存在，复用");
                        }

                        // 保存或更新流元数据
                        // v5.1: flow_key改为"socket_key:dst_port"支持多用户
                        string meta_private_ip = client_ipv4.empty() ? real_client_ip : client_ipv4;
                        string flow_key = socket_key + ":" + to_string(dst_port);
                        (*flow_metadata)[flow_key] = {msg_conn_id, src_port, dst_port,
                                                     real_client_ip, meta_private_ip};

                        Logger::debug("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(dst_port) +
                                    "] 流元数据已保存 (conn_id=" + to_string(msg_conn_id) +
                                    ", private_ip=" + meta_private_ip + ")");
                    }

                    // ===== v5.0关键修改: 发送前替换payload中的客户端IP为代理IP =====
                    // 让游戏服务器认为所有流量来自代理服务器
                    string private_ip = client_ipv4.empty() ? real_client_ip : client_ipv4;

                    Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(dst_port) +
                                "] 准备替换payload: " + private_ip + " -> " + proxy_ip_for_lambda);

                    int replaced_send = replace_ip_in_payload(
                        const_cast<uint8_t*>(payload.data()),
                        payload.size(),
                        private_ip,
                        proxy_ip_for_lambda,  // v5.0: 替换为代理IP而不是TCP源IP
                        0,  // UDP tunnel 没有 conn_id
                        session_uuid
                    );

                    if (replaced_send > 0) {
                        Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(dst_port) +
                                   "] ✓ 已替换发送payload中的IP: " + private_ip + " -> " +
                                   proxy_ip_for_lambda + " (替换" + to_string(replaced_send) + "处)");
                    }

                    // v4.7.0: 使用源端口的socket发送到目标端口
                    // v5.1修复: 使用socket_key获取此客户端的socket
                    int udp_fd = (*udp_sockets)[socket_key];

                    // 解析游戏服务器地址
                    struct addrinfo hints{}, *result = nullptr;
                    hints.ai_family = AF_UNSPEC;
                    hints.ai_socktype = SOCK_DGRAM;
                    hints.ai_protocol = IPPROTO_UDP;

                    string port_str = to_string(dst_port);
                    int ret = getaddrinfo(config.game_server_ip.c_str(), port_str.c_str(),
                                        &hints, &result);

                    if (ret == 0 && result != nullptr) {
                        int sent = sendto(udp_fd, payload.data(), payload.size(), 0,
                                        result->ai_addr, result->ai_addrlen);
                        freeaddrinfo(result);

                        if (sent > 0) {
                            Logger::info("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(dst_port) +
                                        "] ✓ 成功发送UDP数据: " + config.game_server_ip + ":" +
                                        to_string(dst_port) + " (" + to_string(sent) + "字节)");
                        } else {
                            Logger::error("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(dst_port) +
                                         "] ✗ UDP发送失败 (errno=" + to_string(errno) +
                                         ": " + strerror(errno) + ")");
                        }
                    } else {
                        Logger::error("[UDP Tunnel|src=" + to_string(src_port) + "|dst=" + to_string(dst_port) +
                                     "] DNS解析失败: " + config.game_server_ip);
                    }
                }
            }

            // 清理
            *running = false;
            Logger::info("[UDP Tunnel] 开始清理资源");

            // **关键修复v3.5.1**: 先shutdown再close所有UDP sockets,强制让阻塞的recvfrom()返回
            // v5.1修复: pair.first已是string类型，无需to_string()
            for (auto& pair : *udp_sockets) {
                Logger::debug("[UDP Tunnel|" + pair.first + "] 关闭UDP socket");
                shutdown(pair.second, SHUT_RDWR);  // 先shutdown,强制唤醒阻塞的recvfrom()
                close(pair.second);
            }

            // 然后等待所有UDP接收线程结束
            for (auto& pair : *udp_recv_threads) {
                if (pair.second && pair.second->joinable()) {
                    Logger::debug("[UDP Tunnel|" + pair.first + "] 等待接收线程结束");
                    pair.second->join();
                }
                // 智能指针自动释放，无需delete - 修复了原来第1324行的线程安全问题!
            }

            close(client_fd);
            Logger::info("[UDP Tunnel] 连接已关闭");

        } catch (exception& e) {
            Logger::error("[UDP Tunnel] 异常: " + string(e.what()));
            close(client_fd);
        }
    }
};

// ==================== 辅助函数 ====================
int extract_number(const string& str) {
    string num_str;
    for (char c : str) {
        if (isdigit(c)) {
            num_str += c;
        }
    }
    if (num_str.empty()) return 0;

    try {
        return stoi(num_str);
    } catch (...) {
        return 0;
    }
}

// ==================== 配置文件加载 ====================
GlobalConfig load_config(const string& filename) {
    GlobalConfig global_config;

    ifstream file(filename);
    if (!file.is_open()) {
        Logger::warning("配置文件不存在: " + filename + "，使用默认配置");
        // 返回包含一个默认服务器的配置
        ServerConfig default_server;
        global_config.servers.push_back(default_server);
        return global_config;
    }

    string line;
    bool in_servers_array = false;
    bool in_server_object = false;
    ServerConfig current_server;

    while (getline(file, line)) {
        // 检查是否进入servers数组
        if (line.find("\"servers\"") != string::npos && line.find("[") != string::npos) {
            in_servers_array = true;
            continue;
        }

        // 检查是否退出servers数组
        if (in_servers_array && line.find("]") != string::npos) {
            string trimmed = line;
            trimmed.erase(0, trimmed.find_first_not_of(" \t"));
            if (trimmed[0] == ']') {
                in_servers_array = false;
                continue;
            }
        }

        // 在servers数组中
        if (in_servers_array) {
            // 检查是否开始一个新的server对象
            if (line.find("{") != string::npos && !in_server_object) {
                in_server_object = true;
                current_server = ServerConfig();  // 重置为默认值
                continue;
            }

            // 检查是否结束当前server对象
            if (in_server_object && line.find("}") != string::npos) {
                string trimmed = line;
                trimmed.erase(0, trimmed.find_first_not_of(" \t"));
                if (trimmed[0] == '}') {
                    global_config.servers.push_back(current_server);
                    in_server_object = false;
                    continue;
                }
            }

            // 解析server对象内的字段
            if (in_server_object) {
                if (line.find("\"name\"") != string::npos) {
                    size_t start = line.find("\"", line.find(":")) + 1;
                    size_t end = line.find("\"", start);
                    if (start != string::npos && end != string::npos) {
                        current_server.name = line.substr(start, end - start);
                    }
                }
                else if (line.find("\"listen_port\"") != string::npos) {
                    size_t pos = line.find(":");
                    if (pos != string::npos) {
                        string value = line.substr(pos + 1);
                        int num = extract_number(value);
                        if (num > 0) current_server.listen_port = num;
                    }
                }
                else if (line.find("\"game_server_ip\"") != string::npos) {
                    size_t start = line.find("\"", line.find(":")) + 1;
                    size_t end = line.find("\"", start);
                    if (start != string::npos && end != string::npos) {
                        current_server.game_server_ip = line.substr(start, end - start);
                    }
                }
                else if (line.find("\"max_connections\"") != string::npos) {
                    size_t pos = line.find(":");
                    if (pos != string::npos) {
                        string value = line.substr(pos + 1);
                        int num = extract_number(value);
                        if (num > 0) current_server.max_connections = num;
                    }
                }
            }
        }

        // 解析全局log_level
        if (!in_servers_array && line.find("\"log_level\"") != string::npos) {
            size_t start = line.find("\"", line.find(":")) + 1;
            size_t end = line.find("\"", start);
            if (start != string::npos && end != string::npos) {
                global_config.log_level = line.substr(start, end - start);
            }
        }

        // 解析API配置 (简单判断:在api_config后面的字段)
        static bool in_api_config = false;
        if (line.find("\"api_config\"") != string::npos) {
            in_api_config = true;
        }
        if (in_api_config && line.find("}") != string::npos) {
            string trimmed = line;
            trimmed.erase(0, trimmed.find_first_not_of(" \t"));
            if (trimmed[0] == '}') {
                in_api_config = false;
            }
        }

        if (in_api_config && !in_servers_array) {
            if (line.find("\"enabled\"") != string::npos) {
                if (line.find("true") != string::npos) {
                    global_config.api_config.enabled = true;
                } else if (line.find("false") != string::npos) {
                    global_config.api_config.enabled = false;
                }
            }
            else if (line.find("\"port\"") != string::npos) {
                size_t pos = line.find(":");
                if (pos != string::npos) {
                    string value = line.substr(pos + 1);
                    int num = extract_number(value);
                    if (num > 0) global_config.api_config.port = num;
                }
            }
            else if (line.find("\"tunnel_server_ip\"") != string::npos) {
                size_t start = line.find("\"", line.find(":")) + 1;
                size_t end = line.find("\"", start);
                if (start != string::npos && end != string::npos) {
                    global_config.api_config.tunnel_server_ip = line.substr(start, end - start);
                }
            }
        }
    }

    // 如果没有解析到任何服务器，添加默认服务器
    if (global_config.servers.empty()) {
        Logger::warning("配置文件中未找到服务器配置，使用默认配置");
        ServerConfig default_server;
        global_config.servers.push_back(default_server);
    }

    return global_config;
}

// ==================== 生成默认配置文件 ====================
bool generate_default_config(const string& filename) {
    ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    file << "// ============================================================\n";
    file << "// DNF隧道服务器配置文件 v3.6.1\n";
    file << "// 支持多端口/多游戏服务器\n";
    file << "// ============================================================\n";
    file << "//\n";
    file << "// 配置说明:\n";
    file << "//\n";
    file << "// name             - 服务器名称（用于日志标识）\n";
    file << "// listen_port      - 隧道服务器监听端口（客户端连接此端口）\n";
    file << "//                    范围: 1-65535，建议使用 30000-40000\n";
    file << "//                    不同服务器必须使用不同端口\n";
    file << "//\n";
    file << "// game_server_ip   - 游戏服务器的内网IP地址\n";
    file << "//                    这是隧道服务器要转发到的目标服务器\n";
    file << "//\n";
    file << "// max_connections  - 最大并发连接数\n";
    file << "//                    根据服务器性能调整，建议 50-500\n";
    file << "//\n";
    file << "// download_url     - 客户端下载地址（可选）\n";
    file << "//                    HTTP/HTTPS链接，用于客户端GUI显示下载地址\n";
    file << "//                    例如: http://192.168.2.22:5244/d/DOF/客户端.7z\n";
    file << "//\n";
    file << "// log_level        - 全局日志级别: DEBUG, INFO, WARN, ERROR\n";
    file << "//                    生产环境建议使用 INFO\n";
    file << "//\n";
    file << "// ============================================================\n";
    file << "//\n";
    file << "// 配置示例:\n";
    file << "//\n";
    file << "// 示例1: 单个游戏服务器\n";
    file << "// {\n";
    file << "//   \"servers\": [\n";
    file << "//     {\n";
    file << "//       \"name\": \"游戏服1\",\n";
    file << "//       \"listen_port\": 33223,\n";
    file << "//       \"game_server_ip\": \"192.168.2.110\",\n";
    file << "//       \"max_connections\": 100,\n";
    file << "//       \"download_url\": \"http://192.168.2.22:5244/d/DOF/客户端.7z\"\n";
    file << "//     }\n";
    file << "//   ],\n";
    file << "//   \"log_level\": \"INFO\"\n";
    file << "// }\n";
    file << "//\n";
    file << "// 示例2: 多个游戏服务器（推荐）\n";
    file << "// {\n";
    file << "//   \"servers\": [\n";
    file << "//     {\n";
    file << "//       \"name\": \"游戏服1\",\n";
    file << "//       \"listen_port\": 33223,\n";
    file << "//       \"game_server_ip\": \"192.168.2.110\",\n";
    file << "//       \"max_connections\": 100,\n";
    file << "//       \"download_url\": \"http://192.168.2.22:5244/d/DOF/服务器1/客户端.7z\"\n";
    file << "//     },\n";
    file << "//     {\n";
    file << "//       \"name\": \"游戏服2\",\n";
    file << "//       \"listen_port\": 33224,\n";
    file << "//       \"game_server_ip\": \"192.168.2.100\",\n";
    file << "//       \"max_connections\": 100,\n";
    file << "//       \"download_url\": \"http://192.168.2.22:5244/d/DOF/服务器2/客户端.7z\"\n";
    file << "//     },\n";
    file << "//     {\n";
    file << "//       \"name\": \"游戏服3\",\n";
    file << "//       \"listen_port\": 33225,\n";
    file << "//       \"game_server_ip\": \"192.168.2.11\",\n";
    file << "//       \"max_connections\": 100,\n";
    file << "//       \"download_url\": \"http://192.168.2.22:5244/d/DOF/服务器3/客户端.7z\"\n";
    file << "//     }\n";
    file << "//   ],\n";
    file << "//   \"log_level\": \"INFO\"\n";
    file << "// }\n";
    file << "//\n";
    file << "// ============================================================\n";
    file << "//\n";
    file << "// 注意事项:\n";
    file << "// 1. 一个程序可以管理多个游戏服务器\n";
    file << "// 2. 每个服务器必须使用不同的监听端口\n";
    file << "// 3. 服务器名称用于日志中区分不同服务器\n";
    file << "// 4. 所有服务器共享同一个日志文件\n";
    file << "// 5. 客户端连接时需要指定对应的端口号\n";
    file << "//\n";
    file << "// ============================================================\n";
    file << "\n";
    file << "{\n";
    file << "  \"servers\": [\n";
    file << "    {\n";
    file << "      \"name\": \"游戏服1\",\n";
    file << "      \"listen_port\": 33223,\n";
    file << "      \"game_server_ip\": \"192.168.2.110\",\n";
    file << "      \"max_connections\": 100,\n";
    file << "      \"download_url\": \"http://example.com/download/client.7z\"\n";
    file << "    }\n";
    file << "  ],\n";
    file << "  \"log_level\": \"INFO\",\n";
    file << "  \"api_config\": {\n";
    file << "    \"enabled\": true,\n";
    file << "    \"port\": 33231,\n";
    file << "    \"tunnel_server_ip\": \"192.168.2.75\"\n";
    file << "  }\n";
    file << "}\n";

    file.close();
    return true;
}

// ==================== 全局服务器实例管理 ====================
// 全局变量：所有运行中的 TunnelServer 实例
struct RunningServer {
    ServerConfig config;
    shared_ptr<TunnelServer> instance;
    shared_ptr<std::thread> server_thread;  // 重命名避免命名冲突
};

vector<RunningServer> g_running_servers;
mutex g_running_servers_mutex;
string g_config_file_path;  // 配置文件路径

// 比对配置，查找需要新增/删除的服务器
void reload_tunnel_servers() {
    Logger::info("========================================");
    Logger::info("开始热重载隧道服务器配置...");
    Logger::info("========================================");

    // 1. 重新加载配置文件
    if (g_config_file_path.empty()) {
        Logger::error("配置文件路径未初始化");
        return;
    }

    GlobalConfig new_config = load_config(g_config_file_path);

    lock_guard<mutex> lock(g_running_servers_mutex);

    // 2. 构建当前运行服务器的映射 (key: listen_port)
    map<int, RunningServer*> current_map;
    for (auto& rs : g_running_servers) {
        current_map[rs.config.listen_port] = &rs;
    }

    // 3. 构建新配置的映射
    map<int, ServerConfig> new_map;
    for (const auto& cfg : new_config.servers) {
        new_map[cfg.listen_port] = cfg;
    }

    // 4. 查找需要新增的服务器
    int added = 0, removed = 0, modified = 0;

    for (const auto& pair : new_map) {
        int port = pair.first;
        const ServerConfig& new_cfg = pair.second;

        if (current_map.find(port) == current_map.end()) {
            // 新增服务器
            Logger::info("[热重载] 新增服务器: [" + new_cfg.name + "] 端口:" +
                        to_string(port) + " → " + new_cfg.game_server_ip);

            auto server = make_shared<TunnelServer>(new_cfg);
            auto t = make_shared<thread>([server]() {
                server->start();
            });

            RunningServer rs;
            rs.config = new_cfg;
            rs.instance = server;
            rs.server_thread = t;
            g_running_servers.push_back(rs);

            added++;
        } else {
            // 检查是否修改
            RunningServer* current = current_map[port];
            if (current->config.game_server_ip != new_cfg.game_server_ip ||
                current->config.name != new_cfg.name) {

                Logger::info("[热重载] 检测到配置修改: [" + new_cfg.name + "] 端口:" + to_string(port));
                Logger::info("  旧游戏服务器: " + current->config.game_server_ip);
                Logger::info("  新游戏服务器: " + new_cfg.game_server_ip);
                Logger::info("  注意: 已有连接仍使用旧配置，新连接将使用新配置");
                Logger::info("  建议: 如需完全切换，请使用 systemctl restart");

                // 先停止旧实例
                if (current->instance) {
                    current->instance->stop();
                }
                if (current->server_thread && current->server_thread->joinable()) {
                    current->server_thread->join();
                }

                // 启动新实例
                auto server = make_shared<TunnelServer>(new_cfg);
                auto t = make_shared<thread>([server]() {
                    server->start();
                });

                current->config = new_cfg;
                current->instance = server;
                current->server_thread = t;

                modified++;
            }
        }
    }

    // 5. 查找需要删除的服务器
    vector<RunningServer> new_running_servers;
    for (auto& rs : g_running_servers) {
        if (new_map.find(rs.config.listen_port) == new_map.end()) {
            // 删除服务器
            Logger::info("[热重载] 删除服务器: [" + rs.config.name + "] 端口:" +
                        to_string(rs.config.listen_port));

            if (rs.instance) {
                rs.instance->stop();
            }
            if (rs.server_thread && rs.server_thread->joinable()) {
                rs.server_thread->join();
            }

            removed++;
        } else {
            new_running_servers.push_back(rs);
        }
    }
    g_running_servers = new_running_servers;

    // 6. 也重载 TCP Config Server 的配置
    reload_tcp_config();

    Logger::info("========================================");
    Logger::info("热重载完成: 新增" + to_string(added) + "个, 修改" +
                to_string(modified) + "个, 删除" + to_string(removed) + "个");
    Logger::info("当前运行服务器数量: " + to_string(g_running_servers.size()));
    Logger::info("========================================");
}

// ==================== 信号处理 - 捕获崩溃并记录日志 ====================
// 使用异步信号安全的函数记录崩溃信息
void signal_handler(int signum) {
    // SIGHUP: 重新加载配置
    if (signum == SIGHUP) {
        reload_tunnel_servers();
        return;
    }

    // 其他信号: 崩溃处理
    // 只使用异步信号安全的函数: write(), backtrace(), backtrace_symbols_fd()
    const char* msg1 = "\n========================================\n!!! CRASH DETECTED !!!\nSignal: ";
    ssize_t ret;  // 用于接收返回值，避免编译警告
    ret = write(STDERR_FILENO, msg1, strlen(msg1));
    (void)ret;  // 明确忽略返回值

    const char* signal_name = "UNKNOWN";
    if (signum == SIGSEGV) signal_name = "SIGSEGV";
    else if (signum == SIGABRT) signal_name = "SIGABRT";
    else if (signum == SIGFPE) signal_name = "SIGFPE";
    else if (signum == SIGILL) signal_name = "SIGILL";

    ret = write(STDERR_FILENO, signal_name, strlen(signal_name));
    (void)ret;
    ret = write(STDERR_FILENO, "\n", 1);
    (void)ret;

    // 获取并打印堆栈跟踪 (使用fd版本,异步信号安全)
    const char* msg2 = "Stack trace:\n";
    ret = write(STDERR_FILENO, msg2, strlen(msg2));
    (void)ret;

    void* callstack[128];
    int frames = backtrace(callstack, 128);
    backtrace_symbols_fd(callstack, frames, STDERR_FILENO);  // 异步信号安全!

    const char* msg3 = "========================================\nTerminating...\n";
    ret = write(STDERR_FILENO, msg3, strlen(msg3));
    (void)ret;

    // 恢复默认信号处理并重新触发，以便生成core dump
    signal(signum, SIG_DFL);
    raise(signum);
}

void install_signal_handlers() {
    signal(SIGSEGV, signal_handler);  // Segmentation Fault
    signal(SIGABRT, signal_handler);  // Abort
    signal(SIGFPE, signal_handler);   // Floating Point Exception
    signal(SIGILL, signal_handler);   // Illegal Instruction
    signal(SIGHUP, signal_handler);   // Hangup - 用于热重载配置

    Logger::info("信号处理器已安装 (SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGHUP)");
}

// ==================== 主函数 ====================
int main() {
    // 创建log目录（如果不存在）
    mkdir("log", 0755);

    // 生成带时间戳的日志文件名(使用北京时间UTC+8)
    auto now = chrono::system_clock::now();
    auto beijing_time = chrono::system_clock::to_time_t(now + chrono::hours(8));
    stringstream log_filename;
    log_filename << "log/server_log_" << put_time(gmtime(&beijing_time), "%Y%m%d_%H%M%S") << ".txt";

    // 初始化日志系统
    Logger::init(log_filename.str());

    // 安装信号处理器
    install_signal_handlers();

    cout << "============================================================" << endl;
    cout << "DNF多端口隧道服务器 v3.6.1 (C++ 版本 - Python架构)" << endl;
    cout << "支持 TCP + UDP 双协议转发 + 多游戏服务器" << endl;
    cout << "v3.6.1: forward后主动reset shared_ptr防止析构在线程内执行" << endl;
    cout << "============================================================" << endl;
    cout << endl;

    const string config_file = "config.json";

    // 检查配置文件是否存在
    ifstream check_file(config_file);
    bool config_exists = check_file.is_open();
    check_file.close();

    if (!config_exists) {
        // 首次运行 - 生成配置文件并退出
        cout << "========================================" << endl;
        cout << "首次运行检测" << endl;
        cout << "========================================" << endl;
        cout << endl;

        Logger::info("未找到配置文件: " + config_file);
        Logger::info("正在生成默认配置文件...");

        if (generate_default_config(config_file)) {
            cout << "✓ 配置文件已生成: " << config_file << endl;
            cout << endl;
            cout << "请按照以下步骤配置服务器:" << endl;
            cout << "----------------------------------------" << endl;
            cout << "1. 编辑 " << config_file << " 文件" << endl;
            cout << "2. 在 servers 数组中配置游戏服务器:" << endl;
            cout << "   - name: 服务器名称（用于日志标识）" << endl;
            cout << "   - listen_port: 监听端口（不同服务器用不同端口）" << endl;
            cout << "   - game_server_ip: 游戏服务器IP地址" << endl;
            cout << "   - max_connections: 最大连接数" << endl;
            cout << "3. 可以配置多个服务器，一个程序管理所有" << endl;
            cout << "4. 保存文件后重新运行本程序" << endl;
            cout << "----------------------------------------" << endl;
            cout << endl;

            Logger::info("配置文件已生成，等待用户配置");
            Logger::info("程序退出，请修改配置后重新启动");
            Logger::close();
            return 0;  // 正常退出
        } else {
            cout << "✗ 生成配置文件失败" << endl;
            Logger::error("无法创建配置文件: " + config_file);
            Logger::close();
            return 1;  // 错误退出
        }
    }

    // 配置文件存在 - 正常加载
    GlobalConfig global_config = load_config(config_file);

    // 保存配置文件路径到全局变量（用于热重载）
    g_config_file_path = config_file;

    // 设置日志级别
    Logger::set_log_level(global_config.log_level);

    Logger::info("配置加载完成，共 " + to_string(global_config.servers.size()) + " 个服务器");
    Logger::info("日志级别: " + global_config.log_level);
    cout << endl;

    // 显示所有服务器配置
    for (size_t i = 0; i < global_config.servers.size(); i++) {
        const ServerConfig& srv = global_config.servers[i];
        Logger::info("[" + srv.name + "] 端口:" + to_string(srv.listen_port) +
                    " → " + srv.game_server_ip +
                    " (最大连接:" + to_string(srv.max_connections) + ")");
    }
    cout << endl;

    Logger::info("正在启动所有隧道服务器...");

    // 创建并启动所有TunnelServer实例，添加到全局管理
    {
        lock_guard<mutex> lock(g_running_servers_mutex);
        for (const ServerConfig& srv_cfg : global_config.servers) {
            auto server = make_shared<TunnelServer>(srv_cfg);
            auto t = make_shared<thread>([server]() {
                server->start();
            });

            RunningServer rs;
            rs.config = srv_cfg;
            rs.instance = server;
            rs.server_thread = t;
            g_running_servers.push_back(rs);
        }
    }

    Logger::info("所有隧道服务器已启动");
    cout << endl;

    // 启动HTTP API服务器 (用于多服务器客户端)
    pthread_t api_thread = 0;
    if (global_config.api_config.enabled) {
        Logger::info("正在启动TCP配置服务器...");
        Logger::info("API配置: 端口=" + to_string(global_config.api_config.port) +
                    ", 隧道服务器IP=" + global_config.api_config.tunnel_server_ip);

        api_thread = start_tcp_config_server(config_file.c_str(),
                                             global_config.api_config.tunnel_server_ip.c_str(),
                                             global_config.api_config.port);
        if (api_thread == 0) {
            Logger::error("TCP配置服务器启动失败");
        } else {
            Logger::info("TCP配置服务器已启动在端口 " + to_string(global_config.api_config.port));
            cout << "TCP配置服务器: " << global_config.api_config.tunnel_server_ip
                 << ":" << global_config.api_config.port << " (协议: GET_SERVERS)" << endl;
        }
    } else {
        Logger::info("HTTP API服务器已禁用 (在config.json中设置api_config.enabled=true启用)");
    }

    cout << endl;
    cout << "服务器正在运行..." << endl;
    cout << "  • 停止服务器: Ctrl+C 或 kill <pid>" << endl;
    cout << "  • 热重载配置: kill -HUP <pid> (支持动态增删服务器)" << endl;
    cout << "  • 查看进程ID: echo $$" << endl;
    cout << "============================================================" << endl;

    // 主线程保持运行，等待信号
    // 注意：热重载时会动态修改 g_running_servers，所以不能简单 join
    while (true) {
        sleep(10);  // 每10秒检查一次

        // 检查是否所有服务器都停止了
        lock_guard<mutex> lock(g_running_servers_mutex);
        bool all_stopped = true;
        for (const auto& rs : g_running_servers) {
            if (rs.instance && rs.instance->is_running()) {
                all_stopped = false;
                break;
            }
        }

        if (all_stopped && !g_running_servers.empty()) {
            Logger::info("所有隧道服务器已停止");
            break;
        }
    }

    // 停止TCP配置服务器
    if (api_thread != 0) {
        Logger::info("正在停止TCP配置服务器...");
        stop_tcp_config_server();
        pthread_join(api_thread, NULL);
        Logger::info("TCP配置服务器已停止");
    }

    // 清理全局服务器实例
    {
        lock_guard<mutex> lock(g_running_servers_mutex);
        g_running_servers.clear();  // 智能指针自动清理，无需手动delete
    }

    Logger::info("所有服务器已正常关闭");
    Logger::close();
    return 0;
}
