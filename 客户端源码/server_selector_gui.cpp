/*
 * 服务器选择GUI窗口实现
 */

#include "server_selector_gui.h"
#include "resource.h"
#include <commctrl.h>
#include <sstream>
#include <thread>
#include <objidl.h>  // IStream
#include <gdiplus.h>
#include <tlhelp32.h>  // 用于进程枚举
#include <uxtheme.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uxtheme.lib")

using namespace Gdiplus;

namespace {
constexpr UINT kMsgLatencyUpdate = WM_APP + 100;
constexpr int kLatencyConnectTimeoutMs = 800;
constexpr UINT_PTR kLatencyWatchdogTimerId = 0x4C41;
constexpr UINT kLatencyWatchdogIntervalMs = 120;
constexpr ULONGLONG kLatencyRttStaleMs = 2500;
constexpr double kLatencyEmaAlpha = 0.35;

ULONGLONG g_last_real_rtt_tick = 0;
double g_smoothed_real_rtt_ms = -1.0;

void ResetRealLatencyState() {
    g_last_real_rtt_tick = 0;
    g_smoothed_real_rtt_ms = -1.0;
}

int SmoothRealLatencyForUi(int raw_ms) {
    if (raw_ms < 0) {
        return -1;
    }

    if (g_smoothed_real_rtt_ms < 0.0) {
        g_smoothed_real_rtt_ms = static_cast<double>(raw_ms);
    } else {
        g_smoothed_real_rtt_ms =
            g_smoothed_real_rtt_ms * (1.0 - kLatencyEmaAlpha) +
            static_cast<double>(raw_ms) * kLatencyEmaAlpha;
    }

    if (g_smoothed_real_rtt_ms > 9999.0) {
        g_smoothed_real_rtt_ms = 9999.0;
    }

    g_last_real_rtt_tick = GetTickCount64();
    return static_cast<int>(g_smoothed_real_rtt_ms + 0.5);
}

int MeasureTcpLatencyMs(const std::string& host, int port, int timeout_ms) {
    if (host.empty() || port <= 0 || port > 65535) {
        return -1;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    const std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result) != 0) {
        return -1;
    }

    int best_latency_ms = -1;
    for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        SOCKET sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        u_long nonblocking = 1;
        if (ioctlsocket(sock, FIONBIO, &nonblocking) == SOCKET_ERROR) {
            closesocket(sock);
            continue;
        }

        ULONGLONG begin = GetTickCount64();
        int conn_result = connect(sock, rp->ai_addr, static_cast<int>(rp->ai_addrlen));
        if (conn_result == 0) {
            int elapsed = static_cast<int>(GetTickCount64() - begin);
            best_latency_ms = (best_latency_ms < 0 || elapsed < best_latency_ms) ? elapsed : best_latency_ms;
            closesocket(sock);
            break;
        }

        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS || err == WSAEALREADY) {
            fd_set write_set;
            FD_ZERO(&write_set);
            FD_SET(sock, &write_set);

            timeval tv{};
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;

            int sel = select(0, nullptr, &write_set, nullptr, &tv);
            if (sel > 0 && FD_ISSET(sock, &write_set)) {
                int so_error = 0;
                int so_len = sizeof(so_error);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &so_len) == 0 &&
                    so_error == 0) {
                    int elapsed = static_cast<int>(GetTickCount64() - begin);
                    best_latency_ms = (best_latency_ms < 0 || elapsed < best_latency_ms) ? elapsed : best_latency_ms;
                    closesocket(sock);
                    break;
                }
            }
        }

        closesocket(sock);
    }

    freeaddrinfo(result);
    return best_latency_ms;
}
}  // namespace

// 使用Windows API结束同名进程（避免创建控制台窗口）
static void TerminateOtherInstances(const char* exe_name, DWORD current_pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    // 转换exe_name为宽字符（因为PROCESSENTRY32使用Unicode）
    WCHAR exe_name_w[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, exe_name, -1, exe_name_w, MAX_PATH);

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe32)) {
        do {
            // 检查进程名是否匹配且不是当前进程
            if (_wcsicmp(pe32.szExeFile, exe_name_w) == 0 && pe32.th32ProcessID != current_pid) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
}

ServerSelectorGUI::ServerSelectorGUI()
    : hwnd(NULL), hInstance(GetModuleHandle(NULL)),
      selected_index(-1), user_confirmed(false), showing_log(false), is_connected(false),
      dialog_should_close(false), child_running(false), child_stdout_read(NULL), child_stdout_write(NULL),
      child_job_object(NULL), hBackgroundBitmap(NULL), bg_width(0), bg_height(0),
      latency_probe_running(false), latency_target_port(0), latency_target_valid(false) {
    ZeroMemory(&child_process, sizeof(child_process));
    ResetRealLatencyState();
}

ServerSelectorGUI::~ServerSelectorGUI() {
    if (hwnd) {
        KillTimer(hwnd, kLatencyWatchdogTimerId);
    }
    StopLatencyProbe();
    // 停止子进程
    StopChildProcess();

    // 释放背景图片
    if (hBackgroundBitmap) {
        DeleteObject(hBackgroundBitmap);
    }

    if (hwnd) {
        DestroyWindow(hwnd);
    }
}

bool ServerSelectorGUI::ShowDialog(const std::vector<ServerInfo>& server_list,
                                   int last_server_id,
                                   ServerInfo& selected_server) {
    servers = server_list;
    selected_index = -1;
    user_confirmed = false;
    dialog_should_close = false;

    // 初始化GDI+
    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // 加载背景图片
    LoadBackgroundImage();

    // 初始化窗口
    if (!InitWindow()) {
        GdiplusShutdown(gdiplusToken);
        return false;
    }

    // 填充服务器列表
    StartLatencyProbe();
    PopulateServerList(last_server_id);

    // 显示窗口
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // 消息循环 - 永远运行，直到程序退出
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 清理GDI+
    GdiplusShutdown(gdiplusToken);

    // 这里永远不会到达（除非用户取消初始化）
    return false;
}

bool ServerSelectorGUI::InitWindow() {
    // 注册窗口类
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"DNFServerSelector";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(245, 247, 250));  // 现代浅灰背景

    // 先注销可能存在的旧类
    UnregisterClassW(L"DNFServerSelector", hInstance);
    RegisterClassW(&wc);

    // 创建窗口（居中显示，增大宽度以容纳3列）
    int screen_width = GetSystemMetrics(SM_CXSCREEN);
    int screen_height = GetSystemMetrics(SM_CYSCREEN);
    int window_width = 800;  // 增大宽度
    int window_height = 620;
    int x = (screen_width - window_width) / 2;
    int y = (screen_height - window_height) / 2;

    hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_LAYERED,  // 去掉置顶，添加分层窗口支持阴影
        L"DNFServerSelector",
        L"选择服务器",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,  // 添加最小化按钮
        x, y, window_width, window_height,
        NULL, NULL, hInstance, this  // 传递this指针
    );

    if (!hwnd) {
        return false;
    }

    // 设置窗口透明度和阴影效果
    SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA);

    // 设置窗口数据（存储this指针）
    SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)this);

    // 创建控件 - 现代化扁平设计
    // 1. 标题文本（更现代的样式）- 居中显示,透明背景
    HWND hTitle = CreateWindowW(
        L"STATIC", L"选择游戏服务器",
        WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
        270, 25, 240, 40,
        hwnd, NULL, hInstance, NULL
    );

    // 设置标题字体（轻量，现代）
    HFONT hTitleFont = CreateFont(
        32, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hTitle, WM_SETFONT, (WPARAM)hTitleFont, TRUE);

    // 2. 分割线
    HWND hDivider = CreateWindowW(
        L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        30, 75, 740, 2,
        hwnd, NULL, hInstance, NULL
    );

    // 3. 服务器按钮将在PopulateServerList中动态创建
    // 预留空间: 30, 95, 740, 320

    // 4. 下载地址区域标签 - 缩短宽度以适应文字
    HWND hLabel = CreateWindowW(
        L"STATIC", L"客户端下载地址",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        30, 430, 160, 28,
        hwnd, (HMENU)IDC_STATIC_LABEL, hInstance, NULL
    );

    // 设置标签字体（加大字体）
    HFONT hLabelFont = CreateFont(
        20, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hLabel, WM_SETFONT, (WPARAM)hLabelFont, TRUE);

    // 5. 下载地址文本框（现代扁平样式）
    HWND hEdit = CreateWindowW(
        L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_READONLY | ES_AUTOHSCROLL,
        30, 463, 740, 38,
        hwnd, (HMENU)IDC_EDIT_DOWNLOAD, hInstance, NULL
    );

    // 设置文本框字体（加大字体）
    HFONT hEditFont = CreateFont(
        18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hEdit, WM_SETFONT, (WPARAM)hEditFont, TRUE);

    // 6. 连接按钮（现代扁平设计，主色调）
    HWND hBtnConnect = CreateWindowW(
        L"BUTTON", L"连接服务器",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
        30, 520, 355, 48,
        hwnd, (HMENU)IDC_BTN_CONNECT, hInstance, NULL
    );

    // 设置按钮字体
    HFONT hButtonFont = CreateFont(
        18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    SendMessage(hBtnConnect, WM_SETFONT, (WPARAM)hButtonFont, TRUE);

    // 7. 取消按钮（次要按钮）
    HWND hBtnCancel = CreateWindowW(
        L"BUTTON", L"取消",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
        415, 520, 355, 48,
        hwnd, (HMENU)IDC_BTN_CANCEL, hInstance, NULL
    );
    SendMessage(hBtnCancel, WM_SETFONT, (WPARAM)hButtonFont, TRUE);

    HWND hLatencyLabel = CreateWindowExW(
        WS_EX_TRANSPARENT,
        L"STATIC", L"\u5EF6\u8FDF:",
        WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE,
        470, 25, 70, 40,
        hwnd, (HMENU)IDC_STATIC_LATENCY_LABEL, hInstance, NULL
    );

    HWND hLatencyValue = CreateWindowW(
        L"STATIC", L"--ms",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        545, 25, 95, 40,
        hwnd, (HMENU)IDC_STATIC_LATENCY_VALUE, hInstance, NULL
    );

    // 8. "查看日志"按钮（放在标题右侧）- 加大字体
    HWND hBtnShowLog = CreateWindowW(
        L"BUTTON", L"查看日志",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
        650, 25, 120, 40,
        hwnd, (HMENU)IDC_BTN_SHOW_LOG, hInstance, NULL
    );
    HFONT hSmallFont = CreateFont(
        18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );
    HFONT hLatencyFont = CreateFont(
        18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas"
    );
    SendMessage(hLatencyLabel, WM_SETFONT, (WPARAM)hSmallFont, TRUE);
    SendMessage(hLatencyValue, WM_SETFONT, (WPARAM)hLatencyFont, TRUE);
    SendMessage(hBtnShowLog, WM_SETFONT, (WPARAM)hSmallFont, TRUE);

    // 9. 日志文本框（多行只读，初始隐藏）
    HWND hEditLog = CreateWindowW(
        L"EDIT", L"",
        WS_CHILD | WS_BORDER | ES_LEFT | ES_READONLY | ES_MULTILINE |
        ES_AUTOVSCROLL | WS_VSCROLL,
        30, 95, 740, 405,
        hwnd, (HMENU)IDC_EDIT_LOG, hInstance, NULL
    );
    SendMessage(hEditLog, WM_SETFONT, (WPARAM)hSmallFont, TRUE);
    // 设置文本框最大长度为5MB，避免日志过多时被截断
    SendMessage(hEditLog, EM_SETLIMITTEXT, 5 * 1024 * 1024, 0);

    // 10. "返回"按钮（初始隐藏）
    HWND hBtnBack = CreateWindowW(
        L"BUTTON", L"返回",
        WS_CHILD | BS_PUSHBUTTON | BS_FLAT,
        30, 520, 740, 48,
        hwnd, (HMENU)IDC_BTN_BACK, hInstance, NULL
    );
    SendMessage(hBtnBack, WM_SETFONT, (WPARAM)hButtonFont, TRUE);

    return true;
}

void ServerSelectorGUI::PopulateServerList(int last_server_id) {
    // 清除旧按钮
    for (HWND btn : server_buttons) {
        if (btn) {
            DestroyWindow(btn);
        }
    }
    server_buttons.clear();

    // 创建按钮字体
    HFONT hButtonFont = CreateFont(
        18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"微软雅黑"
    );

    // 网格布局参数
    const int cols = 3;           // 每行3个
    const int start_x = 30;
    const int start_y = 95;
    const int btn_width = 235;    // 按钮宽度
    const int btn_height = 60;    // 按钮高度
    const int gap_x = 10;         // 水平间距
    const int gap_y = 10;         // 垂直间距

    int default_index = -1;

    // 创建服务器按钮
    for (size_t i = 0; i < servers.size(); i++) {
        int row = i / cols;
        int col = i % cols;

        int x = start_x + col * (btn_width + gap_x);
        int y = start_y + row * (btn_height + gap_y);

        HWND hBtn = CreateWindowW(
            L"BUTTON", servers[i].name.c_str(),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT | BS_MULTILINE,
            x, y, btn_width, btn_height,
            hwnd, (HMENU)(IDC_SERVER_BTN_BASE + i), hInstance, NULL
        );

        SendMessage(hBtn, WM_SETFONT, (WPARAM)hButtonFont, TRUE);
        server_buttons.push_back(hBtn);

        // 如果是上次选择的服务器，记录索引
        if (servers[i].id == last_server_id) {
            default_index = i;
        }
    }

    // 如果有上次选择，自动选中并显示信息
    if (default_index >= 0) {
        selected_index = default_index;
        UpdateServerInfo(default_index);
        // 高亮显示（可选：设置焦点）
        if (default_index < (int)server_buttons.size()) {
            SetFocus(server_buttons[default_index]);
        }
    }

    RefreshLatencyDisplay();
}

void ServerSelectorGUI::UpdateServerInfo(int index) {
    if (index < 0 || index >= (int)servers.size()) {
        SetDlgItemTextW(hwnd, IDC_EDIT_DOWNLOAD, L"");
        return;
    }

    const ServerInfo& info = servers[index];

    // 将 UTF-8 字符串转换为宽字符（支持中文URL）
    if (info.download_url.empty()) {
        SetDlgItemTextW(hwnd, IDC_EDIT_DOWNLOAD, L"");
    } else {
        int len = MultiByteToWideChar(CP_UTF8, 0, info.download_url.c_str(), -1, NULL, 0);
        if (len > 0) {
            wchar_t* wbuf = new wchar_t[len];
            MultiByteToWideChar(CP_UTF8, 0, info.download_url.c_str(), -1, wbuf, len);
            SetDlgItemTextW(hwnd, IDC_EDIT_DOWNLOAD, wbuf);
            delete[] wbuf;
        } else {
            // 转换失败，尝试直接使用 ANSI（适用于纯ASCII URL）
            SetDlgItemTextA(hwnd, IDC_EDIT_DOWNLOAD, info.download_url.c_str());
        }
    }
}

void ServerSelectorGUI::StartLatencyProbe() {
    StopLatencyProbe();
    latency_probe_running.store(true, std::memory_order_release);

    latency_probe_thread = std::thread([this]() {
        std::string last_host;
        int last_port = 0;
        bool has_posted = false;
        int last_posted_latency = -1;
        ULONGLONG last_post_tick = 0;

        while (latency_probe_running.load(std::memory_order_acquire)) {
            std::string host;
            int port = 0;
            bool target_valid = false;
            {
                std::lock_guard<std::mutex> lock(latency_target_mutex);
                host = latency_target_host;
                port = latency_target_port;
                target_valid = latency_target_valid;
            }

            if (!target_valid) {
                Sleep(80);
                continue;
            }

            if (host != last_host || port != last_port) {
                last_host = host;
                last_port = port;
                has_posted = false;
                last_post_tick = 0;
            }

            int latency_ms = MeasureTcpLatencyMs(host, port, kLatencyConnectTimeoutMs);
            if (!latency_probe_running.load(std::memory_order_acquire)) {
                break;
            }

            ULONGLONG now = GetTickCount64();
            bool should_post = false;
            if (!has_posted) {
                should_post = true;
            } else if ((now - last_post_tick) >= 200 && latency_ms != last_posted_latency) {
                should_post = true;
            } else if ((now - last_post_tick) >= 700) {
                should_post = true;
            }

            if (should_post) {
                HWND window = hwnd;
                if (window && IsWindow(window)) {
                    PostMessage(window, kMsgLatencyUpdate, 0, static_cast<LPARAM>(latency_ms));
                }
                has_posted = true;
                last_posted_latency = latency_ms;
                last_post_tick = now;
            }

            Sleep(20);
        }
    });
}

void ServerSelectorGUI::StopLatencyProbe() {
    latency_probe_running.store(false, std::memory_order_release);
    if (latency_probe_thread.joinable()) {
        latency_probe_thread.join();
    }
}

void ServerSelectorGUI::ApplyLatencyText(int latency_ms) {
    if (!hwnd) {
        return;
    }

    HWND hLatencyValue = GetDlgItem(hwnd, IDC_STATIC_LATENCY_VALUE);
    if (!hLatencyValue) {
        return;
    }

    wchar_t text[64];
    if (latency_ms >= 0) {
        swprintf_s(text, L"%dms", latency_ms);
    } else {
        wcscpy_s(text, L"--ms");
    }

    wchar_t current[64] = {};
    GetWindowTextW(hLatencyValue, current, _countof(current));
    if (wcscmp(current, text) == 0) {
        return;
    }

    SetWindowTextW(hLatencyValue, text);
    InvalidateRect(hLatencyValue, NULL, FALSE);
}

void ServerSelectorGUI::RefreshLatencyDisplay() {
    bool target_valid = false;
    {
        std::lock_guard<std::mutex> lock(latency_target_mutex);
        if (selected_index >= 0 && selected_index < (int)servers.size()) {
            const ServerInfo& info = servers[selected_index];
            latency_target_host = info.tunnel_server_ip;
            latency_target_port = info.tunnel_port;
            latency_target_valid =
                !latency_target_host.empty() &&
                latency_target_port > 0 &&
                latency_target_port <= 65535;
            target_valid = latency_target_valid;
        } else {
            latency_target_host.clear();
            latency_target_port = 0;
            latency_target_valid = false;
        }
    }

    if (!target_valid) {
        ApplyLatencyText(-1);
    }
}

void ServerSelectorGUI::OnConnectClick() {
    if (selected_index < 0 || selected_index >= (int)servers.size()) {
        MessageBoxW(hwnd, L"请先选择一个服务器！", L"提示", MB_OK | MB_ICONWARNING);
        return;
    }

    // 切换到日志页面
    ShowLogPage();

    // 清空日志（重新连接时）
    HWND hEditLog = GetDlgItem(hwnd, IDC_EDIT_LOG);
    if (hEditLog) {
        SetWindowTextW(hEditLog, L"");
    }

    // 显示连接信息
    std::wstring server_name = servers[selected_index].name;
    AppendLog(L"=== 开始连接 ===\r\n");
    AppendLog(L"服务器: " + server_name + L"\r\n");
    AppendLog(L"正在启动隧道进程...\r\n\r\n");

    // 启动子进程
    if (StartChildProcess(servers[selected_index])) {
        user_confirmed = true;
        is_connected = true;  // 标记为已连接
        StopLatencyProbe();   // 连接后切换为子进程心跳RTT，不再使用connect探测
        ResetRealLatencyState();
        SetTimer(hwnd, kLatencyWatchdogTimerId, kLatencyWatchdogIntervalMs, NULL);
        AppendLog(L"✓ 隧道进程已启动\r\n\r\n");
    } else {
        AppendLog(L"✗ 启动隧道进程失败\r\n\r\n");
        MessageBoxW(hwnd, L"启动隧道进程失败", L"错误", MB_OK | MB_ICONERROR);
    }
}

void ServerSelectorGUI::OnCancelClick() {
    // 停止子进程
    StopChildProcess();
    StopLatencyProbe();
    if (hwnd) {
        KillTimer(hwnd, kLatencyWatchdogTimerId);
    }
    ResetRealLatencyState();

    // 获取当前进程名（不包含路径）
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    char* exe_name = strrchr(exe_path, '\\');
    if (!exe_name) exe_name = exe_path;
    else exe_name++; // 跳过 '\'

    // 强制终止所有同名进程（除了当前进程）
    DWORD current_pid = GetCurrentProcessId();
    TerminateOtherInstances(exe_name, current_pid);

    // 等待一下确保子进程被终止
    Sleep(300);

    // 直接终止整个程序（包括当前进程）
    ExitProcess(0);
}

void ServerSelectorGUI::OnListSelectionChange() {
    // 保留此函数以保持兼容性，但不再使用
}

void ServerSelectorGUI::OnServerButtonClick(int server_index) {
    if (server_index >= 0 && server_index < (int)servers.size()) {
        selected_index = server_index;
        UpdateServerInfo(server_index);
        RefreshLatencyDisplay();

        // 视觉反馈：高亮选中的按钮
        for (size_t i = 0; i < server_buttons.size(); i++) {
            if ((int)i == server_index) {
                // 选中状态：设置焦点
                SetFocus(server_buttons[i]);
            }
        }
    }
}

void ServerSelectorGUI::ShowLogPage() {
    showing_log = true;

    // 隐藏服务器选择页面的控件
    for (HWND btn : server_buttons) {
        ShowWindow(btn, SW_HIDE);
    }
    ShowWindow(GetDlgItem(hwnd, IDC_STATIC_LABEL), SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_EDIT_DOWNLOAD), SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_CONNECT), SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_CANCEL), SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_SHOW_LOG), SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_STATIC_LATENCY_LABEL), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_STATIC_LATENCY_VALUE), SW_SHOW);
    RefreshLatencyDisplay();

    // 显示日志页面的控件
    ShowWindow(GetDlgItem(hwnd, IDC_EDIT_LOG), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_BACK), SW_SHOW);

    // 添加初始日志
    AppendLog(L"=== 日志系统已启动 ===\r\n");
    AppendLog(L"等待连接...\r\n");
}

void ServerSelectorGUI::ShowServerPage() {
    showing_log = false;
    if (hwnd) {
        KillTimer(hwnd, kLatencyWatchdogTimerId);
    }
    ResetRealLatencyState();

    // 显示服务器选择页面的控件
    for (HWND btn : server_buttons) {
        ShowWindow(btn, SW_SHOW);
    }
    ShowWindow(GetDlgItem(hwnd, IDC_STATIC_LABEL), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_EDIT_DOWNLOAD), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_CONNECT), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_CANCEL), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_SHOW_LOG), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_STATIC_LATENCY_LABEL), SW_SHOW);
    ShowWindow(GetDlgItem(hwnd, IDC_STATIC_LATENCY_VALUE), SW_SHOW);
    if (!latency_probe_running.load(std::memory_order_acquire)) {
        StartLatencyProbe();
    }
    RefreshLatencyDisplay();

    // 隐藏日志页面的控件
    ShowWindow(GetDlgItem(hwnd, IDC_EDIT_LOG), SW_HIDE);
    ShowWindow(GetDlgItem(hwnd, IDC_BTN_BACK), SW_HIDE);
}

void ServerSelectorGUI::AppendLog(const std::wstring& message) {
    HWND hEditLog = GetDlgItem(hwnd, IDC_EDIT_LOG);
    if (!hEditLog) return;

    // 获取当前文本长度
    int len = GetWindowTextLengthW(hEditLog);

    // 如果日志超过4MB，清除前半部分（保留后半部分）
    const int MAX_LOG_SIZE = 4 * 1024 * 1024;  // 4MB
    if (len > MAX_LOG_SIZE) {
        // 获取当前所有文本
        int bufSize = len + 1;
        wchar_t* buffer = new wchar_t[bufSize];
        GetWindowTextW(hEditLog, buffer, bufSize);

        // 从中间开始保留后半部分
        int halfPoint = len / 2;
        std::wstring keepText = L"...(前半部分日志已清除)\r\n\r\n";
        keepText += (buffer + halfPoint);

        // 设置新文本
        SetWindowTextW(hEditLog, keepText.c_str());
        delete[] buffer;

        // 重新获取长度
        len = GetWindowTextLengthW(hEditLog);
    }

    // 将光标移到末尾
    SendMessageW(hEditLog, EM_SETSEL, len, len);

    // 追加文本
    SendMessageW(hEditLog, EM_REPLACESEL, FALSE, (LPARAM)message.c_str());

    // 滚动到底部
    SendMessageW(hEditLog, EM_SCROLLCARET, 0, 0);
}

// 公共方法：添加日志（供外部调用）
void ServerSelectorGUI::AddLog(const std::wstring& message) {
    AppendLog(message);
}

// 加载背景图片（从资源）
bool ServerSelectorGUI::LoadBackgroundImage() {
    // 从资源加载图片数据（使用RT_RCDATA类型）
    HRSRC hResource = FindResource(hInstance, MAKEINTRESOURCE(IDB_BACKGROUND), RT_RCDATA);
    if (!hResource) {
        // 如果资源加载失败，返回false但不影响程序运行
        return false;
    }

    HGLOBAL hMemory = LoadResource(hInstance, hResource);
    if (!hMemory) return false;

    DWORD dwSize = SizeofResource(hInstance, hResource);
    LPVOID lpAddress = LockResource(hMemory);
    if (!lpAddress) return false;

    // 创建流
    HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, dwSize);
    if (!hGlobal) return false;

    void* pData = GlobalLock(hGlobal);
    memcpy(pData, lpAddress, dwSize);
    GlobalUnlock(hGlobal);

    IStream* pStream = NULL;
    if (CreateStreamOnHGlobal(hGlobal, TRUE, &pStream) != S_OK) {
        GlobalFree(hGlobal);
        return false;
    }

    // 使用GDI+加载图片
    Bitmap* bitmap = Bitmap::FromStream(pStream);
    pStream->Release();

    if (!bitmap || bitmap->GetLastStatus() != Ok) {
        if (bitmap) delete bitmap;
        return false;
    }

    // 转换为HBITMAP
    Color transparent(0, 0, 0, 0);
    bitmap->GetHBITMAP(transparent, &hBackgroundBitmap);
    bg_width = bitmap->GetWidth();
    bg_height = bitmap->GetHeight();

    delete bitmap;
    return true;
}

// 绘制背景
void ServerSelectorGUI::DrawBackground(HDC hdc) {
    if (!hBackgroundBitmap) return;

    // 获取窗口大小
    RECT rect;
    GetClientRect(hwnd, &rect);
    int win_width = rect.right - rect.left;
    int win_height = rect.bottom - rect.top;

    // 创建内存DC
    HDC hdcMem = CreateCompatibleDC(hdc);
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBackgroundBitmap);

    // 使用StretchBlt拉伸图片以填充窗口
    SetStretchBltMode(hdc, HALFTONE);
    StretchBlt(hdc, 0, 0, win_width, win_height,
               hdcMem, 0, 0, bg_width, bg_height,
               SRCCOPY);

    SelectObject(hdcMem, hOldBitmap);
    DeleteDC(hdcMem);
}

// 启动子进程
bool ServerSelectorGUI::StartChildProcess(const ServerInfo& server) {
    // 如果已经有子进程在运行，先停止它
    if (child_running) {
        StopChildProcess();
    }

    // 创建Job对象，用于管理进程树
    child_job_object = CreateJobObject(NULL, NULL);
    if (child_job_object) {
        // 设置Job对象，当主进程关闭时，自动终止所有子进程
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(child_job_object, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
    }

    // 创建管道用于读取子进程输出
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&child_stdout_read, &child_stdout_write, &sa, 0)) {
        if (child_job_object) {
            CloseHandle(child_job_object);
            child_job_object = NULL;
        }
        return false;
    }

    // 确保读取句柄不被继承
    SetHandleInformation(child_stdout_read, HANDLE_FLAG_INHERIT, 0);

    // 准备启动信息
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = child_stdout_write;
    si.hStdOutput = child_stdout_write;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // 隐藏子进程窗口

    ZeroMemory(&child_process, sizeof(child_process));

    // 获取当前程序路径
    char exe_path[MAX_PATH];
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);

    // 构建命令行
    // 格式: "程序路径" --worker <server_id> <game_server_ip> <tunnel_server_ip> <tunnel_port>
    char cmdline[2048];
    sprintf(cmdline, "\"%s\" --worker %d %s %s %d",
            exe_path,
            server.id,
            server.game_server_ip.c_str(),
            server.tunnel_server_ip.c_str(),
            server.tunnel_port);

    // 添加调试日志
    AppendLog(L"启动命令: ");
    int len = MultiByteToWideChar(CP_ACP, 0, cmdline, -1, NULL, 0);
    if (len > 0) {
        wchar_t* wcmdline = new wchar_t[len];
        MultiByteToWideChar(CP_ACP, 0, cmdline, -1, wcmdline, len);
        AppendLog(wcmdline);
        AppendLog(L"\r\n\r\n");
        delete[] wcmdline;
    }

    // 启动子进程
    if (!CreateProcessA(
        NULL,           // 应用程序名
        cmdline,        // 命令行
        NULL,           // 进程安全属性
        NULL,           // 线程安全属性
        TRUE,           // 继承句柄
        CREATE_NO_WINDOW,  // 创建标志：不创建窗口
        NULL,           // 环境变量
        NULL,           // 当前目录
        &si,            // 启动信息
        &child_process  // 进程信息
    )) {
        // 获取错误信息
        DWORD error = GetLastError();
        wchar_t error_msg[256];
        swprintf(error_msg, 256, L"CreateProcess失败，错误码: %d\r\n", error);
        AppendLog(error_msg);
        CloseHandle(child_stdout_read);
        CloseHandle(child_stdout_write);
        child_stdout_read = NULL;
        child_stdout_write = NULL;
        if (child_job_object) {
            CloseHandle(child_job_object);
            child_job_object = NULL;
        }
        return false;
    }

    // 将子进程加入Job对象
    if (child_job_object) {
        AssignProcessToJobObject(child_job_object, child_process.hProcess);
    }

    // 关闭写入句柄（子进程会使用它）
    CloseHandle(child_stdout_write);
    child_stdout_write = NULL;

    child_running = true;

    // 启动一个线程来读取子进程输出
    std::thread([this]() {
        ReadChildOutput();
    }).detach();

    return true;
}

// 停止子进程
void ServerSelectorGUI::StopChildProcess() {
    if (!child_running) {
        return;
    }

    child_running = false;

    // 方法1：关闭Job对象（这会自动终止所有关联的进程）
    if (child_job_object) {
        CloseHandle(child_job_object);
        child_job_object = NULL;
        // 等待一下让进程终止
        Sleep(500);
    }

    // 方法2：如果Job对象失败，使用TerminateProcess
    if (child_process.hProcess) {
        // 检查进程是否还在运行
        DWORD exit_code;
        if (GetExitCodeProcess(child_process.hProcess, &exit_code) && exit_code == STILL_ACTIVE) {
            // 进程还在运行，终止它
            TerminateProcess(child_process.hProcess, 0);
            WaitForSingleObject(child_process.hProcess, 2000);
        }

        CloseHandle(child_process.hProcess);
        CloseHandle(child_process.hThread);
        ZeroMemory(&child_process, sizeof(child_process));
    }

    // 关闭管道
    if (child_stdout_read) {
        CloseHandle(child_stdout_read);
        child_stdout_read = NULL;
    }
}

// 读取子进程输出
void ServerSelectorGUI::ReadChildOutput() {
    char buffer[4096];
    DWORD bytes_read;

    while (child_running && child_stdout_read) {
        if (ReadFile(child_stdout_read, buffer, sizeof(buffer) - 1, &bytes_read, NULL) && bytes_read > 0) {
            buffer[bytes_read] = '\0';

            // 转换为宽字符
            int len = MultiByteToWideChar(CP_UTF8, 0, buffer, -1, NULL, 0);
            if (len > 0) {
                wchar_t* wbuf = new wchar_t[len];
                MultiByteToWideChar(CP_UTF8, 0, buffer, -1, wbuf, len);

                // 添加到日志（使用PostMessage确保线程安全）
                std::wstring* msg = new std::wstring(wbuf);
                PostMessage(hwnd, WM_USER + 1, 0, (LPARAM)msg);

                delete[] wbuf;
            }
        } else {
            break;
        }
    }
}

LRESULT CALLBACK ServerSelectorGUI::WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // 获取this指针
    ServerSelectorGUI* pThis = nullptr;

    if (msg == WM_CREATE) {
        CREATESTRUCT* pCreate = (CREATESTRUCT*)lParam;
        pThis = (ServerSelectorGUI*)pCreate->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)pThis);
    } else {
        pThis = (ServerSelectorGUI*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    }

    if (pThis) {
        switch (msg) {
        case WM_ERASEBKGND: {
            // 绘制背景图片
            HDC hdc = (HDC)wParam;
            pThis->DrawBackground(hdc);
            return 1;  // 返回非零表示我们已经处理了背景擦除
        }

        case WM_CTLCOLORSTATIC: {
            // 让标题和标签STATIC控件使用透明背景，但不包括其他控件
            HWND hControl = (HWND)lParam;
            int ctrlID = GetDlgCtrlID(hControl);

            // 只对标题文本和下载地址标签设置透明背景
            if (ctrlID == IDC_STATIC_LABEL || ctrlID == IDC_STATIC_LATENCY_LABEL || ctrlID == 0) {
                HDC hdcStatic = (HDC)wParam;
                SetBkMode(hdcStatic, TRANSPARENT);
                return (LRESULT)GetStockObject(NULL_BRUSH);
            }
            break;
        }

        case WM_DRAWITEM: {
            // 自定义绘制ListBox项（现代扁平风格）
            LPDRAWITEMSTRUCT lpDIS = (LPDRAWITEMSTRUCT)lParam;
            if (lpDIS->CtlID == IDC_STATIC_LATENCY_VALUE) {
                HDC hDC = lpDIS->hDC;
                RECT rcLocal{};
                GetClientRect(lpDIS->hwndItem, &rcLocal);

                // 由系统绘制父窗口背景，避免手动采样背景导致的“半透明/发虚”感
                if (FAILED(DrawThemeParentBackground(lpDIS->hwndItem, hDC, &rcLocal))) {
                    HBRUSH hBrush = CreateSolidBrush(RGB(245, 247, 250));
                    FillRect(hDC, &rcLocal, hBrush);
                    DeleteObject(hBrush);
                }

                wchar_t text[64] = {};
                GetWindowTextW(lpDIS->hwndItem, text, _countof(text));

                SetBkMode(hDC, TRANSPARENT);
                SetTextColor(hDC, RGB(20, 20, 20));
                HFONT hFont = (HFONT)SendMessageW(lpDIS->hwndItem, WM_GETFONT, 0, 0);
                HFONT hOldFont = (HFONT)SelectObject(hDC, hFont);
                DrawTextW(hDC, text, -1, &rcLocal, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                SelectObject(hDC, hOldFont);

                return TRUE;
            }

            if (lpDIS->CtlID == IDC_SERVER_LIST) {
                // 获取设备上下文
                HDC hDC = lpDIS->hDC;
                RECT rcItem = lpDIS->rcItem;

                // 判断是否选中
                bool isSelected = (lpDIS->itemState & ODS_SELECTED) != 0;
                bool isFocused = (lpDIS->itemState & ODS_FOCUS) != 0;

                // 设置背景颜色（现代扁平设计）- 使用透明背景
                COLORREF bgColor;
                COLORREF textColor;

                if (isSelected) {
                    // 选中状态：现代蓝色（类似Windows 11）
                    bgColor = RGB(0, 120, 215);
                    textColor = RGB(255, 255, 255);
                } else {
                    // 未选中状态：透明背景
                    bgColor = RGB(245, 247, 250);
                    textColor = RGB(32, 32, 32);
                }

                // 填充背景
                HBRUSH hBrush = CreateSolidBrush(bgColor);
                FillRect(hDC, &rcItem, hBrush);
                DeleteObject(hBrush);

                // 绘制聚焦框（使用现代虚线边框）
                if (isFocused && !isSelected) {
                    HPEN hPen = CreatePen(PS_DOT, 1, RGB(0, 120, 215));
                    HPEN hOldPen = (HPEN)SelectObject(hDC, hPen);
                    HBRUSH hOldBrush = (HBRUSH)SelectObject(hDC, GetStockObject(NULL_BRUSH));

                    Rectangle(hDC, rcItem.left + 2, rcItem.top + 2,
                             rcItem.right - 2, rcItem.bottom - 2);

                    SelectObject(hDC, hOldPen);
                    SelectObject(hDC, hOldBrush);
                    DeleteObject(hPen);
                }

                // 获取文本
                if (lpDIS->itemID != (UINT)-1) {
                    wchar_t text[256];
                    SendMessageW(lpDIS->hwndItem, LB_GETTEXT, lpDIS->itemID, (LPARAM)text);

                    // 设置文本属性
                    SetBkMode(hDC, TRANSPARENT);
                    SetTextColor(hDC, textColor);

                    // 使用控件的字体
                    HFONT hFont = (HFONT)SendMessageW(lpDIS->hwndItem, WM_GETFONT, 0, 0);
                    HFONT hOldFont = (HFONT)SelectObject(hDC, hFont);

                    // 绘制文本（带左侧内边距）
                    RECT rcText = rcItem;
                    rcText.left += 15;  // 左侧内边距
                    rcText.right -= 15; // 右侧内边距

                    DrawTextW(hDC, text, -1, &rcText,
                             DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

                    SelectObject(hDC, hOldFont);
                }

                return TRUE;
            }
            break;
        }

        case WM_COMMAND:
            if (HIWORD(wParam) == BN_CLICKED) {
                int ctrl_id = LOWORD(wParam);
                if (ctrl_id == IDC_BTN_CONNECT) {
                    pThis->OnConnectClick();
                    return 0;
                } else if (ctrl_id == IDC_BTN_CANCEL) {
                    pThis->OnCancelClick();
                    return 0;
                } else if (ctrl_id == IDC_BTN_SHOW_LOG) {
                    // 切换到日志页面
                    pThis->ShowLogPage();
                    return 0;
                } else if (ctrl_id == IDC_BTN_BACK) {
                    // 返回服务器选择页面
                    if (pThis->is_connected) {
                        // 如果已连接，提示用户
                        int result = MessageBoxW(hwnd,
                                                L"当前已建立连接\n\n返回服务器选择页面将断开连接\n确定要继续吗？",
                                                L"确认",
                                                MB_YESNO | MB_ICONQUESTION);
                        if (result == IDYES) {
                            // 停止子进程
                            pThis->AppendLog(L"\n=== 正在断开连接 ===\r\n");
                            pThis->StopChildProcess();
                            pThis->AppendLog(L"✓ 已断开连接\r\n\r\n");

                            pThis->is_connected = false;
                            pThis->user_confirmed = false;
                            pThis->ShowServerPage();
                        }
                    } else {
                        // 未连接，直接返回
                        pThis->ShowServerPage();
                    }
                    return 0;
                } else if (ctrl_id >= IDC_SERVER_BTN_BASE && ctrl_id < IDC_SERVER_BTN_BASE + 100) {
                    // 服务器按钮点击
                    int server_index = ctrl_id - IDC_SERVER_BTN_BASE;
                    pThis->OnServerButtonClick(server_index);
                    return 0;
                }
            } else if (HIWORD(wParam) == LBN_SELCHANGE) {
                pThis->OnListSelectionChange();
                return 0;
            } else if (HIWORD(wParam) == LBN_DBLCLK) {
                // 双击直接连接
                pThis->OnConnectClick();
                return 0;
            }
            break;

        case kMsgLatencyUpdate:
            if (!pThis->is_connected) {
                pThis->ApplyLatencyText(static_cast<int>(lParam));
            }
            return 0;

        case WM_TIMER:
            if (wParam == kLatencyWatchdogTimerId) {
                if (!pThis->is_connected) {
                    KillTimer(hwnd, kLatencyWatchdogTimerId);
                    return 0;
                }

                ULONGLONG now = GetTickCount64();
                // 首个真实RTT到来前保留当前显示值；只有拿到过RTT后才做超时回退
                if (g_last_real_rtt_tick != 0 &&
                    (now - g_last_real_rtt_tick) > kLatencyRttStaleMs) {
                    pThis->ApplyLatencyText(-1);
                }
                return 0;
            }
            break;

        case WM_USER + 1:
            // 接收从子进程读取线程发送的日志消息
            if (pThis && lParam) {
                std::wstring* msg = (std::wstring*)lParam;

                // 解析子进程输出中的真实RTT标记: [LATENCY_RTT] 23
                static std::wstring s_pending_log;
                s_pending_log += *msg;

                size_t line_start = 0;
                while (true) {
                    size_t line_end = s_pending_log.find(L'\n', line_start);
                    if (line_end == std::wstring::npos) {
                        if (line_start > 0) {
                            s_pending_log.erase(0, line_start);
                        }
                        // 防止极端情况下缓存无限增长
                        const size_t kMaxPending = 4096;
                        if (s_pending_log.size() > kMaxPending) {
                            s_pending_log.erase(0, s_pending_log.size() - kMaxPending);
                        }
                        break;
                    }

                    std::wstring line = s_pending_log.substr(line_start, line_end - line_start);
                    const std::wstring marker = L"[LATENCY_RTT]";
                    size_t marker_pos = line.find(marker);
                    if (marker_pos != std::wstring::npos) {
                        size_t pos = marker_pos + marker.length();
                        while (pos < line.size() && (line[pos] < L'0' || line[pos] > L'9')) {
                            ++pos;
                        }

                        int rtt_ms = 0;
                        bool has_digits = false;
                        while (pos < line.size() && line[pos] >= L'0' && line[pos] <= L'9') {
                            has_digits = true;
                            rtt_ms = rtt_ms * 10 + (line[pos] - L'0');
                            ++pos;
                        }

                        if (has_digits && pThis->is_connected) {
                            pThis->ApplyLatencyText(SmoothRealLatencyForUi(rtt_ms));
                        }
                    }

                    line_start = line_end + 1;
                }

                pThis->AppendLog(*msg);
                delete msg;
            }
            return 0;

        case WM_CLOSE:
            pThis->OnCancelClick();
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}
