#ifndef AUTO_UPDATER_H
#define AUTO_UPDATER_H

#include <string>
#include <windows.h>

// 自动更新模块
// 基于MD5校验检测更新，提示用户，下载并替换程序

struct UpdateInfo {
    std::string latest_md5;          // 最新版本的MD5哈希值
    std::string download_url;        // 下载地址
    std::string current_md5;         // 当前程序的MD5哈希值
};

class AutoUpdater {
public:
    AutoUpdater();
    ~AutoUpdater();

    // 计算当前exe文件的MD5哈希值
    // md5_hash: 输出参数，32位小写十六进制字符串
    // 返回: true=成功, false=失败
    bool CalculateSelfMD5(std::string& md5_hash);

    // 从服务器获取最新版本的MD5
    // api_url: 配置服务器地址
    // api_port: 配置服务器端口
    // info: 输出参数，更新信息
    // error_msg: 输出参数，错误信息
    // 返回: true=成功获取, false=失败
    bool GetLatestMD5(const std::string& api_url, int api_port,
                      UpdateInfo& info, std::wstring& error_msg);

    // 检查是否需要更新（MD5对比）
    // current_md5: 当前程序MD5
    // latest_md5: 服务器最新MD5
    // 返回: true=需要更新, false=不需要
    bool NeedsUpdate(const std::string& current_md5,
                     const std::string& latest_md5);

    // 显示更新提示并执行更新
    // info: 更新信息
    // 返回: true=用户确认更新, false=用户取消
    bool PromptAndUpdate(const UpdateInfo& info);

private:
    // 获取当前exe路径
    std::string GetCurrentExePath();

    // 创建更新批处理脚本
    // download_url: 下载地址
    // exe_path: 当前exe路径
    // 返回: 批处理脚本路径
    std::string CreateUpdateScript(const std::string& download_url,
                                   const std::string& exe_path);

    // 启动更新脚本
    // script_path: 脚本路径
    // 返回: true=成功启动, false=失败
    bool LaunchUpdateScript(const std::string& script_path);

    // MD5计算辅助函数
    void MD5Transform(unsigned int state[4], const unsigned char block[64]);
    void MD5Init();
    void MD5Update(const unsigned char* input, unsigned int inputLen);
    void MD5Final(unsigned char digest[16]);
    std::string MD5DigestToHex(const unsigned char digest[16]);

    // MD5上下文
    unsigned int md5_state[4];
    unsigned int md5_count[2];
    unsigned char md5_buffer[64];
};

#endif // AUTO_UPDATER_H
