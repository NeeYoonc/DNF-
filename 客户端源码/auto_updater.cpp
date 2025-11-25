#include "auto_updater.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

// MD5算法常量
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

AutoUpdater::AutoUpdater() {
}

AutoUpdater::~AutoUpdater() {
}

void AutoUpdater::MD5Init() {
    md5_count[0] = md5_count[1] = 0;
    md5_state[0] = 0x67452301;
    md5_state[1] = 0xefcdab89;
    md5_state[2] = 0x98badcfe;
    md5_state[3] = 0x10325476;
}

void AutoUpdater::MD5Transform(unsigned int state[4], const unsigned char block[64]) {
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

void AutoUpdater::MD5Update(const unsigned char* input, unsigned int inputLen) {
    unsigned int i, index, partLen;

    index = (unsigned int)((md5_count[0] >> 3) & 0x3F);

    if ((md5_count[0] += ((unsigned int)inputLen << 3)) < ((unsigned int)inputLen << 3)) {
        md5_count[1]++;
    }
    md5_count[1] += ((unsigned int)inputLen >> 29);

    partLen = 64 - index;

    if (inputLen >= partLen) {
        memcpy(&md5_buffer[index], input, partLen);
        MD5Transform(md5_state, md5_buffer);

        for (i = partLen; i + 63 < inputLen; i += 64) {
            MD5Transform(md5_state, &input[i]);
        }

        index = 0;
    } else {
        i = 0;
    }

    memcpy(&md5_buffer[index], &input[i], inputLen - i);
}

void AutoUpdater::MD5Final(unsigned char digest[16]) {
    unsigned char bits[8];
    unsigned int index, padLen;

    for (int i = 0, j = 0; j < 8; i++, j += 4) {
        bits[j] = (unsigned char)(md5_count[i] & 0xff);
        bits[j+1] = (unsigned char)((md5_count[i] >> 8) & 0xff);
        bits[j+2] = (unsigned char)((md5_count[i] >> 16) & 0xff);
        bits[j+3] = (unsigned char)((md5_count[i] >> 24) & 0xff);
    }

    index = (unsigned int)((md5_count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    MD5Update(PADDING, padLen);

    MD5Update(bits, 8);

    for (int i = 0, j = 0; j < 16; i++, j += 4) {
        digest[j] = (unsigned char)(md5_state[i] & 0xff);
        digest[j+1] = (unsigned char)((md5_state[i] >> 8) & 0xff);
        digest[j+2] = (unsigned char)((md5_state[i] >> 16) & 0xff);
        digest[j+3] = (unsigned char)((md5_state[i] >> 24) & 0xff);
    }
}

std::string AutoUpdater::MD5DigestToHex(const unsigned char digest[16]) {
    char hex[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&hex[i * 2], "%02x", digest[i]);
    }
    hex[32] = '\0';
    return std::string(hex);
}

std::string AutoUpdater::GetCurrentExePath() {
    char exe_path[MAX_PATH];
    if (GetModuleFileNameA(NULL, exe_path, MAX_PATH) == 0) {
        return "";
    }
    return std::string(exe_path);
}

bool AutoUpdater::CalculateSelfMD5(std::string& md5_hash) {
    std::string exe_path = GetCurrentExePath();
    if (exe_path.empty()) {
        return false;
    }

    // 打开文件
    std::ifstream file(exe_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // 初始化MD5
    MD5Init();

    // 分块读取文件并计算MD5
    const int BUFFER_SIZE = 8192;
    unsigned char buffer[BUFFER_SIZE];

    while (file.good()) {
        file.read((char*)buffer, BUFFER_SIZE);
        std::streamsize bytes_read = file.gcount();
        if (bytes_read > 0) {
            MD5Update(buffer, (unsigned int)bytes_read);
        }
    }

    file.close();

    // 完成MD5计算
    unsigned char digest[16];
    MD5Final(digest);

    // 转换为十六进制字符串
    md5_hash = MD5DigestToHex(digest);

    return true;
}

bool AutoUpdater::NeedsUpdate(const std::string& current_md5,
                               const std::string& latest_md5) {
    // 转换为小写进行比较
    std::string cur = current_md5;
    std::string lat = latest_md5;

    std::transform(cur.begin(), cur.end(), cur.begin(), ::tolower);
    std::transform(lat.begin(), lat.end(), lat.begin(), ::tolower);

    // MD5不一致则需要更新
    return cur != lat;
}

bool AutoUpdater::GetLatestMD5(const std::string& api_url, int api_port,
                                UpdateInfo& info, std::wstring& error_msg) {
    // 初始化Winsock
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        error_msg = L"WSAStartup失败";
        return false;
    }

    // 解析服务器地址
    struct addrinfo hints{}, *result = nullptr;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(api_port);
    int ret = getaddrinfo(api_url.c_str(), port_str.c_str(), &hints, &result);
    if (ret != 0) {
        error_msg = L"DNS解析失败: " + std::wstring(api_url.begin(), api_url.end());
        WSACleanup();
        return false;
    }

    // 尝试连接
    SOCKET sock = INVALID_SOCKET;
    bool connected = false;

    for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        // 设置超时
        DWORD timeout = 10000;  // 10秒
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        if (connect(sock, rp->ai_addr, (int)rp->ai_addrlen) != SOCKET_ERROR) {
            connected = true;
            break;
        }

        closesocket(sock);
        sock = INVALID_SOCKET;
    }

    freeaddrinfo(result);

    if (!connected) {
        error_msg = L"连接更新服务器失败";
        WSACleanup();
        return false;
    }

    // 发送版本查询请求
    const char* request = "GET_VERSION\n";
    if (send(sock, request, (int)strlen(request), 0) == SOCKET_ERROR) {
        error_msg = L"发送请求失败";
        closesocket(sock);
        WSACleanup();
        return false;
    }

    // 接收响应
    char buffer[4096];
    std::string response;
    int recv_len;

    while ((recv_len = recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[recv_len] = '\0';
        response += buffer;

        // 检查是否收到完整JSON
        if (response.find('}') != std::string::npos) {
            break;
        }
    }

    closesocket(sock);
    WSACleanup();

    if (response.empty()) {
        error_msg = L"服务器无响应";
        return false;
    }

    // 解析JSON响应
    // 期望格式: {"md5":"abc123...","download_url":"http://..."}

    // 解析 md5
    size_t md5_pos = response.find("\"md5\"");
    if (md5_pos == std::string::npos) {
        error_msg = L"响应格式错误: 缺少md5字段";
        return false;
    }
    size_t md5_colon = response.find(":", md5_pos);
    size_t md5_quote1 = response.find("\"", md5_colon);
    size_t md5_quote2 = response.find("\"", md5_quote1 + 1);
    if (md5_quote1 == std::string::npos || md5_quote2 == std::string::npos) {
        error_msg = L"响应格式错误: md5解析失败";
        return false;
    }
    info.latest_md5 = response.substr(md5_quote1 + 1, md5_quote2 - md5_quote1 - 1);

    // 解析 download_url
    size_t url_pos = response.find("\"download_url\"");
    if (url_pos == std::string::npos) {
        error_msg = L"响应格式错误: 缺少download_url字段";
        return false;
    }
    size_t url_colon = response.find(":", url_pos);
    size_t url_quote1 = response.find("\"", url_colon);
    size_t url_quote2 = response.find("\"", url_quote1 + 1);
    if (url_quote1 == std::string::npos || url_quote2 == std::string::npos) {
        error_msg = L"响应格式错误: download_url解析失败";
        return false;
    }
    info.download_url = response.substr(url_quote1 + 1, url_quote2 - url_quote1 - 1);

    return true;
}

std::string AutoUpdater::CreateUpdateScript(const std::string& download_url,
                                             const std::string& exe_path) {
    // 将批处理脚本生成在exe所在目录，这样可以用 %~dp0 获取当前目录
    // 避免中文路径编码问题
    std::string exe_dir = exe_path;
    std::string exe_name = exe_path;
    size_t last_slash = exe_path.find_last_of("\\/");
    if (last_slash != std::string::npos) {
        exe_dir = exe_path.substr(0, last_slash + 1);
        exe_name = exe_path.substr(last_slash + 1);
    } else {
        exe_dir = "";
    }

    // 从exe文件名提取应用名称（去掉.exe后缀）
    std::string app_name = exe_name;
    if (app_name.length() > 4 && app_name.substr(app_name.length() - 4) == ".exe") {
        app_name = app_name.substr(0, app_name.length() - 4);
    }

    std::string script_path = exe_dir + app_name + "_update.bat";

    // 创建批处理脚本
    std::ofstream script(script_path);
    if (!script.is_open()) {
        return "";
    }

    // 转义URL中的%字符（批处理中%会被当成环境变量）
    std::string escaped_url = download_url;
    size_t pos = 0;
    while ((pos = escaped_url.find('%', pos)) != std::string::npos) {
        escaped_url.replace(pos, 1, "%%");
        pos += 2;  // 跳过已替换的%%
    }

    script << "@echo off\n";
    script << "chcp 65001 >nul\n";
    script << "title 自动更新程序\n";
    script << "color 0A\n";
    script << "echo ============================================\n";
    script << "echo            自动更新程序\n";
    script << "echo ============================================\n";
    script << "echo.\n";
    script << "echo 正在准备更新...\n";
    script << "timeout /t 2 /nobreak >nul\n";
    script << "echo.\n";

    // 批处理脚本已经在exe所在目录，使用 %~dp0 获取脚本目录（也就是exe目录）
    // 完全避免在批处理中硬编码路径

    script << "rem 使用脚本所在目录作为工作目录\n";
    script << "cd /d \"%~dp0\"\n";
    script << "echo.\n";

    // 从批处理脚本文件名推断exe文件名（避免中文编码问题）
    // 批处理脚本名：xxx_update.bat -> exe名：xxx.exe
    script << "rem 从脚本文件名推断exe文件名\n";
    script << "set \"SCRIPT_NAME=%~n0\"\n";
    script << "set \"EXE_NAME=%SCRIPT_NAME:_update=%\"\n";
    script << "set \"EXE_FILE=%EXE_NAME%.exe\"\n";
    script << "set \"DOWNLOAD_FILE=%TEMP%\\%SCRIPT_NAME%_temp.exe\"\n";

    // 下载文件到临时目录（使用 -s 静默模式，隐藏进度条）
    script << "echo [1/4] 正在下载更新文件...\n";
    script << "curl -s -L --user-agent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\" --referer \"" << escaped_url << "\" --location-trusted -o \"%DOWNLOAD_FILE%\" \"" << escaped_url << "\"\n";
    script << "if %errorlevel% neq 0 (\n";
    script << "    echo.\n";
    script << "    echo [错误] 下载失败！\n";
    script << "    echo.\n";
    script << "    pause\n";
    script << "    exit /b 1\n";
    script << ")\n";

    // 验证下载的文件
    script << "if not exist \"%DOWNLOAD_FILE%\" (\n";
    script << "    echo [错误] 下载的文件不存在！\n";
    script << "    pause\n";
    script << "    exit /b 1\n";
    script << ")\n";

    // 检查文件大小
    script << "for %%F in (\"%DOWNLOAD_FILE%\") do set size=%%~zF\n";
    script << "if %size% LSS 102400 (\n";
    script << "    echo [错误] 下载的文件无效！\n";
    script << "    del /f \"%DOWNLOAD_FILE%\" >nul 2>&1\n";
    script << "    pause\n";
    script << "    exit /b 1\n";
    script << ")\n";
    script << "echo      下载完成 ^(文件大小: %size% 字节^)\n";
    script << "echo.\n";

    // 检查当前目录下的exe文件
    script << "if not exist \"%EXE_FILE%\" (\n";
    script << "    echo [错误] 找不到程序文件！\n";
    script << "    pause\n";
    script << "    exit /b 1\n";
    script << ")\n";

    // 强制结束旧进程
    script << "echo [2/4] 正在停止旧版本程序...\n";
    script << "taskkill /f /im \"%EXE_FILE%\" >nul 2>&1\n";
    script << "timeout /t 1 /nobreak >nul\n";
    script << "echo.\n";

    // 在当前目录操作文件（使用相对路径，只用文件名）
    script << "if exist \"%EXE_FILE%.bak\" del /f \"%EXE_FILE%.bak\" >nul 2>&1\n";

    script << "echo [3/4] 正在安装新版本...\n";
    script << "ren \"%EXE_FILE%\" \"%EXE_NAME%.exe.bak\" >nul 2>&1\n";
    script << "if exist \"%EXE_FILE%\" (\n";
    script << "    echo [错误] 无法替换文件，程序可能仍在运行！\n";
    script << "    pause\n";
    script << "    exit /b 1\n";
    script << ")\n";

    // 复制新文件到当前目录
    script << "copy /y \"%DOWNLOAD_FILE%\" \"%EXE_FILE%\" >nul 2>&1\n";
    script << "if not exist \"%EXE_FILE%\" (\n";
    script << "    echo [错误] 文件安装失败！\n";
    script << "    echo 正在恢复备份...\n";
    script << "    ren \"%EXE_NAME%.exe.bak\" \"%EXE_NAME%.exe\" >nul 2>&1\n";
    script << "    pause\n";
    script << "    exit /b 1\n";
    script << ")\n";
    script << "echo      安装完成\n";
    script << "echo.\n";

    // 清理临时文件和备份
    script << "del /f \"%DOWNLOAD_FILE%\" >nul 2>&1\n";
    script << "del /f \"%EXE_FILE%.bak\" >nul 2>&1\n";

    // 启动新程序（使用相对路径）
    script << "echo [4/4] 正在启动新版本程序...\n";
    script << "start \"\" \"%EXE_FILE%\"\n";
    script << "timeout /t 1 /nobreak >nul\n";
    script << "echo.\n";

    script << "echo ============================================\n";
    script << "echo       更新完成！程序已重新启动\n";
    script << "echo ============================================\n";
    script << "echo.\n";
    script << "timeout /t 3 /nobreak >nul\n";

    // 移除隐藏属性并删除自身
    script << "attrib -h \"%~f0\" >nul 2>&1\n";
    script << "del /f \"%~f0\" >nul 2>&1\n";
    script << "exit /b 0\n";

    script.close();

    // 将批处理脚本设置为隐藏属性
    SetFileAttributesA(script_path.c_str(), FILE_ATTRIBUTE_HIDDEN);

    return script_path;
}

bool AutoUpdater::LaunchUpdateScript(const std::string& script_path) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    std::string cmd = "cmd.exe /c \"" + script_path + "\"";

    if (!CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return false;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return true;
}

bool AutoUpdater::PromptAndUpdate(const UpdateInfo& info) {
    // 构建提示消息
    std::wstring message = L"检测到软件更新！\n\n";

    // 显示MD5信息（部分显示）
    std::wstring cur_md5(info.current_md5.begin(), info.current_md5.end());
    std::wstring lat_md5(info.latest_md5.begin(), info.latest_md5.end());

    message += L"当前版本MD5: " + cur_md5.substr(0, 8) + L"...\n";
    message += L"最新版本MD5: " + lat_md5.substr(0, 8) + L"...\n\n";

    message += L"点击\"确定\"立即更新，程序将自动下载并重启。\n";
    message += L"点击\"取消\"跳过本次更新。";

    int result = MessageBoxW(NULL, message.c_str(), L"软件更新",
                            MB_OKCANCEL | MB_ICONINFORMATION | MB_TOPMOST);

    if (result != IDOK) {
        return false;
    }

    std::string exe_path = GetCurrentExePath();
    if (exe_path.empty()) {
        MessageBoxW(NULL, L"无法获取程序路径", L"更新错误", MB_OK | MB_ICONERROR);
        return false;
    }

    std::string script_path = CreateUpdateScript(info.download_url, exe_path);
    if (script_path.empty()) {
        MessageBoxW(NULL, L"无法创建更新脚本", L"更新错误", MB_OK | MB_ICONERROR);
        return false;
    }

    if (!LaunchUpdateScript(script_path)) {
        MessageBoxW(NULL, L"无法启动更新程序", L"更新错误", MB_OK | MB_ICONERROR);
        return false;
    }

    ExitProcess(0);

    return true;
}
