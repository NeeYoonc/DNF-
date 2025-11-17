/*
 * DNF代理客户端 - 多服务器版配置注入工具 v1.1
 * 内置多服务器客户端二进制,追加API配置生成最终exe
 * v1.1 更新: 自动生成MD5校验文件服务端
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>
#include <algorithm>
#include <ctime>
#include <cstring>

#include "embedded_client_multiserver.h"  // 内置多服务器客户端二进制

using namespace std;

// ==================== MD5 算法实现 ====================

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) { \
    (a) += F((b), (c), (d)) + (x) + (unsigned int)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

#define GG(a, b, c, d, x, s, ac) { \
    (a) += G((b), (c), (d)) + (x) + (unsigned int)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

#define HH(a, b, c, d, x, s, ac) { \
    (a) += H((b), (c), (d)) + (x) + (unsigned int)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

#define II(a, b, c, d, x, s, ac) { \
    (a) += I((b), (c), (d)) + (x) + (unsigned int)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

static unsigned char PADDING[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

class MD5Calculator {
private:
    unsigned int state[4];
    unsigned int count[2];
    unsigned char buffer[64];

    void Transform(unsigned int state[4], const unsigned char block[64]) {
        unsigned int a = state[0], b = state[1], c = state[2], d = state[3], x[16];

        for (int i = 0, j = 0; j < 64; i++, j += 4) {
            x[i] = ((unsigned int)block[j]) | (((unsigned int)block[j+1]) << 8) |
                   (((unsigned int)block[j+2]) << 16) | (((unsigned int)block[j+3]) << 24);
        }

        // Round 1
        FF(a, b, c, d, x[0], S11, 0xd76aa478);
        FF(d, a, b, c, x[1], S12, 0xe8c7b756);
        FF(c, d, a, b, x[2], S13, 0x242070db);
        FF(b, c, d, a, x[3], S14, 0xc1bdceee);
        FF(a, b, c, d, x[4], S11, 0xf57c0faf);
        FF(d, a, b, c, x[5], S12, 0x4787c62a);
        FF(c, d, a, b, x[6], S13, 0xa8304613);
        FF(b, c, d, a, x[7], S14, 0xfd469501);
        FF(a, b, c, d, x[8], S11, 0x698098d8);
        FF(d, a, b, c, x[9], S12, 0x8b44f7af);
        FF(c, d, a, b, x[10], S13, 0xffff5bb1);
        FF(b, c, d, a, x[11], S14, 0x895cd7be);
        FF(a, b, c, d, x[12], S11, 0x6b901122);
        FF(d, a, b, c, x[13], S12, 0xfd987193);
        FF(c, d, a, b, x[14], S13, 0xa679438e);
        FF(b, c, d, a, x[15], S14, 0x49b40821);

        // Round 2
        GG(a, b, c, d, x[1], S21, 0xf61e2562);
        GG(d, a, b, c, x[6], S22, 0xc040b340);
        GG(c, d, a, b, x[11], S23, 0x265e5a51);
        GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);
        GG(a, b, c, d, x[5], S21, 0xd62f105d);
        GG(d, a, b, c, x[10], S22, 0x2441453);
        GG(c, d, a, b, x[15], S23, 0xd8a1e681);
        GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);
        GG(a, b, c, d, x[9], S21, 0x21e1cde6);
        GG(d, a, b, c, x[14], S22, 0xc33707d6);
        GG(c, d, a, b, x[3], S23, 0xf4d50d87);
        GG(b, c, d, a, x[8], S24, 0x455a14ed);
        GG(a, b, c, d, x[13], S21, 0xa9e3e905);
        GG(d, a, b, c, x[2], S22, 0xfcefa3f8);
        GG(c, d, a, b, x[7], S23, 0x676f02d9);
        GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);

        // Round 3
        HH(a, b, c, d, x[5], S31, 0xfffa3942);
        HH(d, a, b, c, x[8], S32, 0x8771f681);
        HH(c, d, a, b, x[11], S33, 0x6d9d6122);
        HH(b, c, d, a, x[14], S34, 0xfde5380c);
        HH(a, b, c, d, x[1], S31, 0xa4beea44);
        HH(d, a, b, c, x[4], S32, 0x4bdecfa9);
        HH(c, d, a, b, x[7], S33, 0xf6bb4b60);
        HH(b, c, d, a, x[10], S34, 0xbebfbc70);
        HH(a, b, c, d, x[13], S31, 0x289b7ec6);
        HH(d, a, b, c, x[0], S32, 0xeaa127fa);
        HH(c, d, a, b, x[3], S33, 0xd4ef3085);
        HH(b, c, d, a, x[6], S34, 0x4881d05);
        HH(a, b, c, d, x[9], S31, 0xd9d4d039);
        HH(d, a, b, c, x[12], S32, 0xe6db99e5);
        HH(c, d, a, b, x[15], S33, 0x1fa27cf8);
        HH(b, c, d, a, x[2], S34, 0xc4ac5665);

        // Round 4
        II(a, b, c, d, x[0], S41, 0xf4292244);
        II(d, a, b, c, x[7], S42, 0x432aff97);
        II(c, d, a, b, x[14], S43, 0xab9423a7);
        II(b, c, d, a, x[5], S44, 0xfc93a039);
        II(a, b, c, d, x[12], S41, 0x655b59c3);
        II(d, a, b, c, x[3], S42, 0x8f0ccc92);
        II(c, d, a, b, x[10], S43, 0xffeff47d);
        II(b, c, d, a, x[1], S44, 0x85845dd1);
        II(a, b, c, d, x[8], S41, 0x6fa87e4f);
        II(d, a, b, c, x[15], S42, 0xfe2ce6e0);
        II(c, d, a, b, x[6], S43, 0xa3014314);
        II(b, c, d, a, x[13], S44, 0x4e0811a1);
        II(a, b, c, d, x[4], S41, 0xf7537e82);
        II(d, a, b, c, x[11], S42, 0xbd3af235);
        II(c, d, a, b, x[2], S43, 0x2ad7d2bb);
        II(b, c, d, a, x[9], S44, 0xeb86d391);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    void Init() {
        count[0] = count[1] = 0;
        state[0] = 0x67452301;
        state[1] = 0xefcdab89;
        state[2] = 0x98badcfe;
        state[3] = 0x10325476;
    }

    void Update(const unsigned char* input, unsigned int inputLen) {
        unsigned int i, index, partLen;

        index = (unsigned int)((count[0] >> 3) & 0x3F);

        if ((count[0] += ((unsigned int)inputLen << 3)) < ((unsigned int)inputLen << 3)) {
            count[1]++;
        }
        count[1] += ((unsigned int)inputLen >> 29);

        partLen = 64 - index;

        if (inputLen >= partLen) {
            memcpy(&buffer[index], input, partLen);
            Transform(state, buffer);

            for (i = partLen; i + 63 < inputLen; i += 64) {
                Transform(state, &input[i]);
            }

            index = 0;
        } else {
            i = 0;
        }

        memcpy(&buffer[index], &input[i], inputLen - i);
    }

    void Final(unsigned char digest[16]) {
        unsigned char bits[8];
        unsigned int index, padLen;

        for (int i = 0, j = 0; j < 8; i++, j += 4) {
            bits[j] = (unsigned char)(count[i] & 0xff);
            bits[j+1] = (unsigned char)((count[i] >> 8) & 0xff);
            bits[j+2] = (unsigned char)((count[i] >> 16) & 0xff);
            bits[j+3] = (unsigned char)((count[i] >> 24) & 0xff);
        }

        index = (unsigned int)((count[0] >> 3) & 0x3f);
        padLen = (index < 56) ? (56 - index) : (120 - index);
        Update(PADDING, padLen);

        Update(bits, 8);

        for (int i = 0, j = 0; j < 16; i++, j += 4) {
            digest[j] = (unsigned char)(state[i] & 0xff);
            digest[j+1] = (unsigned char)((state[i] >> 8) & 0xff);
            digest[j+2] = (unsigned char)((state[i] >> 16) & 0xff);
            digest[j+3] = (unsigned char)((state[i] >> 24) & 0xff);
        }
    }

public:
    string CalculateFileMD5(const string& filename) {
        ifstream file(filename, ios::binary);
        if (!file.is_open()) {
            return "";
        }

        Init();

        const int BUFFER_SIZE = 8192;
        unsigned char buffer_data[BUFFER_SIZE];

        while (file.good()) {
            file.read((char*)buffer_data, BUFFER_SIZE);
            streamsize bytes_read = file.gcount();
            if (bytes_read > 0) {
                Update(buffer_data, (unsigned int)bytes_read);
            }
        }

        file.close();

        unsigned char digest[16];
        Final(digest);

        char hex[33];
        for (int i = 0; i < 16; i++) {
            sprintf(&hex[i * 2], "%02x", digest[i]);
        }
        hex[32] = '\0';

        return string(hex);
    }
};

// ==================== 工具函数 ====================

// 验证域名格式
bool validate_domain(const string& domain) {
    if (domain.empty()) {
        return false;
    }

    // 域名格式检测
    // 允许字母、数字、连字符、点号,必须包含至少一个点号
    regex domain_pattern("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$");
    if (regex_match(domain, domain_pattern) && domain.find('.') != string::npos) {
        return true;
    }

    return false;
}

// 验证端口号
bool validate_port(int port) {
    return port >= 1 && port <= 65535;
}

// 去除字符串首尾空格
string trim(const string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// 将字符串转换为安全的文件名格式
string sanitize_for_filename(const string& str) {
    string safe = str;
    // 替换所有非法文件名字符为下划线
    const string illegal_chars = "<>:\"/\\|?*";
    for (char c : illegal_chars) {
        replace(safe.begin(), safe.end(), c, '_');
    }
    // 限制长度
    if (safe.length() > 50) {
        safe = safe.substr(0, 50);
    }
    return safe;
}

// ==================== 主程序 ====================

int main() {
    // 设置控制台UTF-8编码 (输入和输出)
    SetConsoleCP(CP_UTF8);        // 输入编码
    SetConsoleOutputCP(CP_UTF8);  // 输出编码
    system("chcp 65001 > nul");

    cout << "============================================" << endl;
    cout << "DNF代理客户端 - 多服务器版配置注入工具 v1.0" << endl;
    cout << "============================================" << endl;
    cout << endl;

    cout << "内置客户端大小: " << (EMBEDDED_CLIENT_SIZE / 1024) << " KB" << endl;
    cout << endl;

    // ==================== 收集配置 ====================
    string api_url;
    int api_port;

    cout << "请输入API服务器配置信息" << endl;
    cout << "--------------------------------------------" << endl;

    // 输入API服务器域名
    while (true) {
        cout << "API服务器域名 [例如: config.server.com]: ";
        string input;
        getline(cin, input);
        input = trim(input);

        if (input.empty()) {
            cout << "✗ 域名不能为空" << endl;
            continue;
        }

        if (validate_domain(input)) {
            api_url = input;
            cout << "✓ 域名格式正确" << endl;
            break;
        } else {
            cout << "✗ 域名格式错误,请重新输入" << endl;
            cout << "  示例: config.server.com 或 api.example.com" << endl;
        }
    }

    // 输入API端口
    while (true) {
        cout << "API端口 [默认: 8080]: ";
        string input;
        getline(cin, input);
        input = trim(input);

        if (input.empty()) {
            api_port = 8080;
            break;
        }

        try {
            api_port = stoi(input);
            if (validate_port(api_port)) {
                cout << "✓ 端口有效" << endl;
                break;
            } else {
                cout << "✗ 端口必须在 1-65535 范围内" << endl;
            }
        } catch (...) {
            cout << "✗ 无效的端口号" << endl;
        }
    }

    cout << endl;
    cout << "============================================" << endl;
    cout << "配置摘要" << endl;
    cout << "============================================" << endl;
    cout << "API服务器域名: " << api_url << endl;
    cout << "API端口:       " << api_port << endl;
    cout << "============================================" << endl;
    cout << endl;

    cout << "API端点将为: http://" << api_url << ":" << api_port << "/api/servers" << endl;
    cout << endl;

    // 确认
    cout << "确认以上配置并生成客户端? (Y/N): ";
    string confirm;
    getline(cin, confirm);
    confirm = trim(confirm);
    transform(confirm.begin(), confirm.end(), confirm.begin(), ::tolower);

    if (confirm != "y" && confirm != "yes") {
        cout << "已取消操作。" << endl;
        system("pause");
        return 0;
    }

    cout << endl;
    cout << "============================================" << endl;
    cout << "开始生成多服务器客户端..." << endl;
    cout << "============================================" << endl;

    // ==================== 生成配置客户端 ====================

    // 构造输出文件名 (使用时间戳以避免文件名冲突和编码问题)
    time_t now = time(NULL);
    stringstream output_name;
    output_name << "DNFProxyClient_MultiServer_" << now << ".exe";
    string exe_name = output_name.str();

    cout << "[1/3] 写入客户端二进制..." << endl;
    cout << "  输出文件: " << exe_name << endl;

    // 写入内置的多服务器客户端二进制
    ofstream output(exe_name, ios::binary);
    if (!output.is_open()) {
        cout << "✗ 错误: 无法创建输出文件: " << exe_name << endl;
        cout << "  可能原因: 权限不足或磁盘空间不足" << endl;
        system("pause");
        return 1;
    }

    output.write((const char*)EMBEDDED_CLIENT_DATA, EMBEDDED_CLIENT_SIZE);
    cout << "✓ 客户端二进制已写入 (" << (EMBEDDED_CLIENT_SIZE / 1024) << " KB)" << endl;

    cout << "[2/3] 追加API配置数据..." << endl;

    // 生成JSON配置 (多服务器版本格式)
    stringstream json;
    json << "[CONFIG_START]";
    json << "{";
    json << "\"config_api_url\":\"" << api_url << "\",";
    json << "\"config_api_port\":" << api_port;
    json << "}";
    json << "[CONFIG_END]";

    string config_data = json.str();
    output.write(config_data.c_str(), config_data.length());
    output.close();

    cout << "✓ 配置已追加 (" << config_data.length() << " 字节)" << endl;

    // 获取最终文件大小
    cout << "[3/4] 验证输出文件..." << endl;
    WIN32_FILE_ATTRIBUTE_DATA file_info;
    if (GetFileAttributesExA(exe_name.c_str(), GetFileExInfoStandard, &file_info)) {
        ULONGLONG file_size = (ULONGLONG(file_info.nFileSizeHigh) << 32) | file_info.nFileSizeLow;
        cout << "✓ 文件已生成: " << exe_name << " (" << (file_size / 1024) << " KB)" << endl;
    } else {
        cout << "✓ 文件已生成: " << exe_name << endl;
    }

    // 计算MD5校验值
    cout << "[4/4] 计算MD5校验值..." << endl;
    MD5Calculator md5_calc;
    string md5_hash = md5_calc.CalculateFileMD5(exe_name);

    if (md5_hash.empty()) {
        cout << "⚠ 警告: MD5计算失败" << endl;
    } else {
        cout << "✓ MD5计算完成: " << md5_hash << endl;

        // 保存MD5到文件
        string md5_filename = exe_name + ".md5";
        ofstream md5_file(md5_filename);
        if (md5_file.is_open()) {
            md5_file << md5_hash;
            md5_file.close();
            cout << "✓ MD5已保存到: " << md5_filename << endl;
        } else {
            cout << "⚠ 警告: 无法保存MD5文件" << endl;
        }
    }

    cout << endl;
    cout << "============================================" << endl;
    cout << "✓ 生成成功!" << endl;
    cout << "============================================" << endl;
    cout << "输出文件: " << exe_name << endl;
    cout << "MD5校验文件: " << exe_name << ".md5" << endl;
    cout << endl;
    cout << "============================================" << endl;
    cout << "MD5校验值 (请设置到服务器)" << endl;
    cout << "============================================" << endl;
    cout << md5_hash << endl;
    cout << "============================================" << endl;
    cout << endl;
    cout << "此程序已包含API配置,启动时将:" << endl;
    cout << "  1. 从 http://" << api_url << ":" << api_port << "/api/servers 获取服务器列表" << endl;
    cout << "  2. 显示GUI选择窗口供用户选择服务器" << endl;
    cout << "  3. 记住用户上次的选择" << endl;
    cout << endl;
    cout << "使用方法:" << endl;
    cout << "  1. 确保API服务器正常运行" << endl;
    cout << "  2. 右键点击 " << exe_name << endl;
    cout << "  3. 选择 \"以管理员身份运行\"" << endl;
    cout << endl;
    cout << "API返回格式要求:" << endl;
    cout << endl;
    cout << "1. GET_SERVERS 命令 - 获取服务器列表:" << endl;
    cout << "  {" << endl;
    cout << "    \"servers\": [" << endl;
    cout << "      {" << endl;
    cout << "        \"id\": 1," << endl;
    cout << "        \"name\": \"服务器名称\"," << endl;
    cout << "        \"game_server_ip\": \"192.168.2.110\"," << endl;
    cout << "        \"tunnel_server_ip\": \"192.168.2.75\"," << endl;
    cout << "        \"tunnel_port\": 33223," << endl;
    cout << "        \"download_url\": \"http://example.com/client.zip\"" << endl;
    cout << "      }" << endl;
    cout << "    ]" << endl;
    cout << "  }" << endl;
    cout << endl;
    cout << "2. GET_VERSION 命令 - 获取最新版本MD5:" << endl;
    cout << "  {" << endl;
    cout << "    \"md5\": \"" << md5_hash << "\"," << endl;
    cout << "    \"download_url\": \"http://example.com/update/client.exe\"" << endl;
    cout << "  }" << endl;
    cout << endl;
    cout << "提示: 请将上面的MD5值设置到服务器的GET_VERSION响应中" << endl;
    cout << endl;

    system("pause");
    return 0;
}
