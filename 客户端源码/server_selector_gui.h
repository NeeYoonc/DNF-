/*
 * 服务器选择GUI窗口
 * 类似DNF频道选择的风格
 */

#ifndef SERVER_SELECTOR_GUI_H
#define SERVER_SELECTOR_GUI_H

#include <windows.h>
#include <vector>
#include <string>
#include "tcp_config_client.h"

// 窗口控件ID
#define IDC_SERVER_LIST    1001
#define IDC_BTN_CONNECT    1002
#define IDC_BTN_CANCEL     1003
#define IDC_STATIC_LABEL   1004  // "下载地址:" 标签
#define IDC_EDIT_DOWNLOAD  1005  // 下载地址文本框（可复制）
#define IDC_BTN_SHOW_LOG   1006  // "查看日志" 按钮
#define IDC_EDIT_LOG       1007  // 日志文本框
#define IDC_BTN_BACK       1008  // "返回" 按钮
#define IDC_BTN_PREV_PAGE  1009  // 上一页
#define IDC_STATIC_PAGE_INFO 1010  // 页码信息
#define IDC_BTN_NEXT_PAGE  1011  // 下一页
#define IDC_SERVER_BTN_BASE 2000  // 服务器按钮ID起始值 (2000+索引)

// 服务器选择器类
class ServerSelectorGUI {
public:
    ServerSelectorGUI();
    ~ServerSelectorGUI();

    // 显示服务器选择窗口（模态对话框）
    // servers: 服务器列表
    // last_server_id: 上次选择的服务器ID（用于高亮显示,如果=0则不高亮）
    // selected_server: 输出选中的服务器
    // 返回: 用户是否选择了服务器（true=选择了, false=点击了取消）
    bool ShowDialog(const std::vector<ServerInfo>& servers,
                   int last_server_id,
                   ServerInfo& selected_server);

    // 添加日志消息（公共方法，供外部调用）
    void AddLog(const std::wstring& message);

    // 获取窗口句柄
    HWND GetHWND() const { return hwnd; }

    // 检查窗口是否仍然存在
    bool IsWindowValid() const { return hwnd != NULL && IsWindow(hwnd); }

private:
    HWND hwnd;
    HINSTANCE hInstance;
    std::vector<ServerInfo> servers;
    int selected_index;
    bool user_confirmed;
    std::vector<HWND> server_buttons;  // 存储服务器按钮句柄
    int current_page;  // 当前页（从0开始）
    int total_pages;  // 总页数
    bool showing_log;  // 是否显示日志页面
    bool is_connected;  // 是否已连接
    bool dialog_should_close;  // 对话框是否应该关闭

    // 子进程管理
    PROCESS_INFORMATION child_process;  // 子进程信息
    HANDLE child_stdout_read;  // 子进程stdout读取句柄
    HANDLE child_stdout_write;  // 子进程stdout写入句柄
    HANDLE child_job_object;  // Job对象，用于管理进程树
    bool child_running;  // 子进程是否在运行

    // 背景图片
    HBITMAP hBackgroundBitmap;  // 背景位图句柄
    int bg_width;  // 背景图片宽度
    int bg_height;  // 背景图片高度

    // 窗口过程函数
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    // 初始化窗口
    bool InitWindow();

    // 背景图片
    bool LoadBackgroundImage();  // 加载背景图片
    void DrawBackground(HDC hdc);  // 绘制背景

    // 子进程管理
    bool StartChildProcess(const ServerInfo& server);  // 启动子进程
    void StopChildProcess();  // 停止子进程
    void ReadChildOutput();  // 读取子进程输出

    // 填充服务器列表
    void PopulateServerList(int last_server_id);
    void UpdateServerButtonLayout();  // 刷新当前页按钮位置
    void ConfigureServerScrollBar();  // 兼容旧接口（不使用滚动条）
    void ScrollServerList(int delta);  // 兼容旧接口（分页切换）
    void UpdatePaginationControls();  // 更新分页控件状态
    void ChangePage(int delta);  // 切换页码

    // 更新服务器详情显示
    void UpdateServerInfo(int index);

    // 处理连接按钮点击
    void OnConnectClick();

    // 处理取消按钮点击
    void OnCancelClick();

    // 处理列表选择变化
    void OnListSelectionChange();

    // 处理服务器按钮点击
    void OnServerButtonClick(int server_index);

    // 切换到日志页面
    void ShowLogPage();

    // 返回服务器选择页面
    void ShowServerPage();

    // 添加日志消息
    void AppendLog(const std::wstring& message);
};

#endif // SERVER_SELECTOR_GUI_H
