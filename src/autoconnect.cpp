// autoconnect.cpp : 定义应用程序的入口点。
//

#include "framework.h"
#include "autoconnect.h"
#include "json.hpp" // 包含 JSON 库 
#include <wchar.h>
#include <locale.h>
#include <tchar.h>
#include <shlwapi.h>
#include <fileapi.h>
#include<errhandlingapi.h>
#include <strsafe.h>
#include <string>
#include <wininet.h>
#include <sstream>  
#include <iomanip>
#include <winsock2.h>  
#pragma comment(lib, "ws2_32.lib")  // 添加对 ws2_32 库的链接  
#include <iostream>
#include <ws2tcpip.h>
#include <fstream>
#include <shellapi.h> // 包含 Shell_NotifyIcon 的头文件
#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")  
using json = nlohmann::json;

#define MAX_LOADSTRING 100
#define IDC_SAVE 88888
#define BT_OK 122
#define TIMER_ID 1 
#define WM_TRAYICON (WM_USER + 1) // 自定义消息，用于处理托盘图标事件

TCHAR szConfigFile[MAX_PATH] = { 0 };
//状态变量
bool auto_connect;
bool auto_start;
int status;
std::string selectedOption; // 存储选中的选项  

// 宽字符到字符串的转换函数  
std::string WideStringToString(const std::wstring& wstr)
{
    int len;
    int slength = (int)wstr.length() + 1;
    len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), slength, 0, 0, 0, 0);
    std::string r(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), slength, &r[0], len, 0, 0);
    return r;
}


std::wstring String2Wstring(std::string wstr)
{
    std::wstring res;
    int len = MultiByteToWideChar(CP_ACP, 0, wstr.c_str(), wstr.size(), nullptr, 0);
    if (len < 0) {
        return res;
    }
    wchar_t* buffer = new wchar_t[len + 1];
    if (buffer == nullptr) {
        return res;
    }
    MultiByteToWideChar(CP_ACP, 0, wstr.c_str(), wstr.size(), buffer, len);
    buffer[len] = '\0';
    res.append(buffer);
    delete[] buffer;
    return res;
}
//Returns the last Win32 error, in string format. Returns an empty string if there is no error.


// 将 TCHAR 转换为 std::string  
std::string TCHARToString(const TCHAR* tcharStr) {
#ifdef UNICODE  
    std::wstring ws(tcharStr);
    return std::string(ws.begin(), ws.end());
#else  
    return std::string(tcharStr);
#endif  
}

// 更新 JSON 配置文件  
void UpdateConfigFile(bool isAutoStart) {
    // 读取现有的 JSON 配置文件  
    std::ifstream inputFile(szConfigFile);
    json config;
    if (inputFile.is_open()) {
        inputFile >> config;
        inputFile.close();
    }

    // 更新配置项  
    config["auto_start"] = isAutoStart; // 假设你要更新的配置项为 "auto_start"  

    // 写回 JSON 配置文件  
    std::ofstream outputFile(szConfigFile);
    if (outputFile.is_open()) {
        outputFile << config.dump(4); // 以 4 个空格缩进格式化输出  
        outputFile.close();
    }
}

//设置开机启动
void SetAutoStart(bool enable)
{
    HKEY hKey;
    // 打开注册表项 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run  
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        KEY_SET_VALUE,
        &hKey) == ERROR_SUCCESS)
    {
        // 获取程序执行路径
        TCHAR szPath[MAX_PATH] = { 0 };
        GetModuleFileName(NULL, szPath, MAX_PATH);
        const wchar_t* programPath = szPath; // 替换为你的程序路径  
        const wchar_t* appName = L"autoconnect"; // 替换为你的程序名称  

        if (enable)
        {
            // 设置程序的路径  
            RegSetValueEx(hKey,
                appName, // 注册表项名称  
                0,
                REG_SZ,
                (const BYTE*)programPath,
                (wcslen(programPath) + 1) * sizeof(wchar_t));
        }
        else
        {
            // 删除注册表项  
            RegDeleteValue(hKey, appName);
        }

        // 关闭注册表项  
        RegCloseKey(hKey);
    }
    else
    {
        MessageBox(NULL, L"无法打开注册表项！", L"错误", MB_ICONERROR);
    }
}

void WriteDefaultConfig(const TCHAR* filePath) {
    
    std::string selected1="401@bjut.edu.cn";
    std::string selected2="7778";
    // 创建一个基本的 JSON 配置模板  
    json defaultConfig = {
        {"username", selected1},
        {"password", selected2},
        {"auto_start", true},
        {"auto_connect", true}
    };

    // 将 TCHAR 路径转换为 std::string  
    std::string path = TCHARToString(filePath);

    // 打开文件并写入默认配置  
    std::ofstream configFile(path);
    if (configFile.is_open()) {
        configFile << defaultConfig.dump(4); // 格式化输出  
        configFile.close();
        OutputDebugString(L"已写入默认配置到文件");
    }
    else {
        OutputDebugString(L"无法打开配置文件进行写入");
    }
}


// URL 编码函数  
std::string URLEncode(const std::string& str) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (auto c : str) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        }
        else {
            escaped << '%' << std::setw(2) << std::uppercase << static_cast<int>(static_cast<unsigned char>(c));
        }
    }

    return escaped.str();
}

// 获取本机 IP 地址（使用 getaddrinfo）  
std::string GetLocalIPAddress() {
    WSADATA wsaData;
    char hostName[256];

    // 初始化 Winsock  
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup 失败。" << std::endl;
        return "";
    }

    // 获取主机名  
    if (gethostname(hostName, sizeof(hostName)) == SOCKET_ERROR) {
        std::cerr << "获取主机名失败。" << std::endl;
        WSACleanup();
        return "";
    }

    // 设置 hints  
    addrinfo hints = { 0 };
    hints.ai_family = AF_INET; // 仅使用 IPv4  
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    // 获取地址信息  
    if (getaddrinfo(hostName, nullptr, &hints, &result) != 0) {
        std::cerr << "getaddrinfo 失败。" << std::endl;
        WSACleanup();
        return "";
    }

    std::string ipAddress;
    // 遍历结果并获取 IP 地址  
    for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        sockaddr_in* sockaddr_ipv4 = reinterpret_cast<sockaddr_in*>(ptr->ai_addr);
        char ipStr[INET_ADDRSTRLEN] = { 0 };
        inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ipStr, sizeof(ipStr));
        if (ipStr[0] != '\0') {
            ipAddress = ipStr;
            break;
        }
    }

    // 清理  
    freeaddrinfo(result);
    WSACleanup();

    return ipAddress;
}

std::string TrimNullCharacters(const std::string& str) {
    size_t end = str.find_last_not_of('\0');
    return (end == std::string::npos) ? "" : str.substr(0, end + 1);
}

int LoginCampusNetwork(const std::string& username, const std::string& password) {
    // 登录 URL  
    std::string loginUrl = "http://10.21.221.98:801/eportal/portal/login";
    //return 0;
    // 自动获取本机 IP 地址  
    std::string localIP = GetLocalIPAddress();
    if (localIP.empty()) {
        std::cerr << "无法获取本机 IP 地址。" << std::endl;
        return 0;
    }
    /*
    // 构建 POST 数据  
    std::ostringstream postDataStream;
    postDataStream << "callback=dr1003"
        << "&login_method=1"
        << "&user_account=" << URLEncode(username)
        << "&user_password=" << URLEncode(password)
        << "&wlan_user_ip=" << URLEncode(localIP)
        << "&wlan_user_ipv6="
        << "&wlan_user_mac=000000000000"
        << "&wlan_ac_ip="
        << "&wlan_ac_name="
        << "&jsVersion=4.2.1"
        << "&terminal_type=1"
        << "&lang=zh-cn"
        << "&v=9064"
        << "&lang=zh";
    */
    // 使用示例  
    //std::string username = "testuser\0"; // 可能包含空字符  
    std::string trimmedUsername = TrimNullCharacters(username);
    std::string trimmedpassword = TrimNullCharacters(password);
    // 构建查询参数  
    std::ostringstream queryParamsStream;
    queryParamsStream << "?callback=dr1003"
        << "&login_method=1"
        << "&user_account=" << URLEncode(trimmedUsername)<< "%40campus"
        << "&user_password=" << URLEncode(trimmedpassword)
        << "&wlan_user_ip=" << URLEncode(localIP)
        << "&wlan_user_ipv6="
        << "&wlan_user_mac=000000000000"
        << "&wlan_ac_ip="
        << "&wlan_ac_name="
        << "&jsVersion=4.2.1"
        << "&terminal_type=1"
        << "&lang=zh-cn"
        << "&v=9064"
        << "&lang=zh";

    //std::string postData = postDataStream.str();
    // 将查询参数添加到 URL  
    std::string fullUrl = loginUrl + queryParamsStream.str();

    // 初始化 WinInet  
    HINTERNET hInternet = InternetOpenA("MyUserAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        //std::cerr << "InternetOpen 失败，错误代码：" << GetLastError() << std::endl;
        return 0;
    }

    // 解析 URL  
    URL_COMPONENTSA urlComponents = { 0 };
    urlComponents.dwStructSize = sizeof(urlComponents);
    char hostName[256] = { 0 };
    char urlPath[1024] = { 0 };
    urlComponents.lpszHostName = hostName;
    urlComponents.dwHostNameLength = sizeof(hostName);
    urlComponents.lpszUrlPath = urlPath;
    urlComponents.dwUrlPathLength = sizeof(urlPath);

    if (!InternetCrackUrlA(fullUrl.c_str(), 0, 0, &urlComponents)) {
        InternetCloseHandle(hInternet);
        return 0;
    }

    // 建立连接  
    HINTERNET hConnect = InternetConnectA(hInternet, hostName, urlComponents.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        //std::cerr << "InternetConnect 失败，错误代码：" << GetLastError() << std::endl;
        InternetCloseHandle(hInternet);
        return 0;
    }

    //  打开请求  
    
   // const char* acceptTypes[] = {"*/*", NULL};
    /*
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", urlComponents.lpszUrlPath, NULL, NULL, acceptTypes, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        //std::cerr << "HttpOpenRequest 失败，错误代码：" << GetLastError() << std::endl;
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }
    */

    // 打开请求，使用 GET 方法  
    const char* acceptTypes[] = { "*/*", NULL };
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", urlComponents.lpszUrlPath, NULL, NULL, acceptTypes, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }

    // 设置请求头  
    //std::string headers = "Content-Type: application/x-www-form-urlencoded";
    // 设置请求头  
    std::string headers = "User-Agent: Mozilla/5.0\r\n";
    headers += "Accept: */*\r\n";
    headers += "Connection: Keep-Alive\r\n";
    if (!HttpAddRequestHeadersA(hRequest, headers.c_str(), -1, HTTP_ADDREQ_FLAG_ADD))
    {
        std::cerr << "HttpAddRequestHeadersA 失败，错误代码: " << GetLastError() << std::endl;
    }

    // 发送请求，不发送请求体  
    BOOL bResult = HttpSendRequestA(hRequest, NULL, 0, NULL, 0);
    if (!bResult) {
        std::cerr << "HttpSendRequest 失败，错误代码：" << GetLastError() << std::endl;
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }

    // 检查HTTP状态码  
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusCodeSize, NULL))
    {
        if (statusCode != 200)
        {
            std::cerr << "HTTP 请求失败，状态码: " << statusCode << std::endl;
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return 0;
        }
    }
    else
    {
        std::cerr << "无法获取 HTTP 状态码。" << std::endl;
    }

    // 读取服务器响应（可选）  
    char buffer[1024];
    DWORD bytesRead = 0;
    std::string response;

    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        //buffer[bytesRead] = '\0';
        response.append(buffer, bytesRead);
        bytesRead = 0;
    }

    // 将 UTF-8 编码的字符串转换为宽字符字符串（UTF-16）  
    int wideCharLength = MultiByteToWideChar(CP_UTF8, 0, response.c_str(), static_cast<int>(response.length()), NULL, 0);
    if (wideCharLength > 0) {
        std::wstring wideResponse(wideCharLength, 0);
        MultiByteToWideChar(CP_UTF8, 0, response.c_str(), static_cast<int>(response.length()), &wideResponse[0], wideCharLength);
        // 提取 JSON 数据  
        size_t startPos = wideResponse.find(L'(');
        size_t endPos = wideResponse.rfind(L')');

        if (startPos != std::wstring::npos && endPos != std::wstring::npos && startPos < endPos) {
            std::wstring jsonWString = wideResponse.substr(startPos + 1, endPos - startPos - 1);

            // 转换为 UTF-8 编码的字符串供 JSON 解析  
            int utf8Length = WideCharToMultiByte(CP_UTF8, 0, jsonWString.c_str(), -1, NULL, 0, NULL, NULL);
            if (utf8Length > 0) {
                std::string jsonString(utf8Length - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, jsonWString.c_str(), -1, &jsonString[0], utf8Length, NULL, NULL);

                // 解析 JSON 数据  
                try {
                    json jsonData = json::parse(jsonString);

                    int result = jsonData.value("result", -1);
                    std::string msg = jsonData.value("msg", "");
                    int ret_code = jsonData.value("ret_code", -1);

                    //std::cout << "result: " << result << std::endl;
                    //std::cout << "msg: " << msg << std::endl;
                    //std::cout << "ret_code: " << ret_code << std::endl;

                   

                    OutputDebugStringW(L"服务器响应：");
                    OutputDebugStringW(wideResponse.c_str());
                    if(result==1)
                    {
                        return 666;
                    }
                    else
                    {
                        return ret_code;
                    }
                    
                }
                catch (const json::parse_error& e) {
                    //std::cerr << "JSON 解析错误：" << e.what() << std::endl;
                    return 0;
                }
            }
            else {
                std::cerr << "宽字符转换为 UTF-8 编码字符串失败。" << std::endl;
                return 0;
            }
        }
        else {
            std::wcerr << L"无法提取 JSON 数据。" << std::endl;
            return 0;
        }
        // 输出宽字符字符串  
        //std::wcout.imbue(std::locale("chs")); // 设置控制台使用中文区域设置  

        //std::wcout << L"服务器响应：" << wideResponse << std::endl;
        // 使用 OutputDebugStringW 输出宽字符串  
        OutputDebugStringW(L"服务器响应：");
        OutputDebugStringW(wideResponse.c_str());

        // 提取 JSON 数据（如果需要处理 JSON）  
        // 可以使用宽字符版本的字符串进行后续处理  

    }
    else {
        // 转换失败，输出错误信息  
        //std::cerr << "无法将服务器响应从 UTF-8 转换为宽字符字符串，错误代码：" << GetLastError() << std::endl;
    }

    // 输出服务器响应（可根据需要进行解析）  
    //std::cout << "服务器响应：" << response << std::endl;
    //std::cout << "服务器响应原始数据：" << response << std::endl

    // 提取 JSON 数据  


    // 清理资源  
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    
}
int LogoutCampusNetwork(const std::string& username, const std::string& password) {
    // 登录 URL  
    std::string loginUrl = "http://10.21.221.98:801/eportal/portal/logout";
    //return 0;
    // 自动获取本机 IP 地址  
    std::string localIP = GetLocalIPAddress();
    if (localIP.empty()) {
        std::cerr << "无法获取本机 IP 地址。" << std::endl;
        return 0;
    }
    // 构建查询参数  
    std::ostringstream queryParamsStream;
    queryParamsStream << "?callback=dr1003"
        << "&login method=1"
        << "&user account=" << "drcom"
        << "&user password=" << "123"
        <<"&ac logout=0"
        <<"&register mode=0"
        << "&wlan user ip=" << URLEncode(localIP)
        << "&wlan user ipv6="
        << "&wlan user mac=000000000000"
        << "&wlan ac ip="
        << "&wlan ac name="
        << "&jsVersion=4.2.1"
        << "&v=9064"
        << "&lang=zh";

    //std::string postData = postDataStream.str();
    // 将查询参数添加到 URL  
    std::string fullUrl = loginUrl + queryParamsStream.str();

    // 初始化 WinInet  
    HINTERNET hInternet = InternetOpenA("MyUserAgent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        //std::cerr << "InternetOpen 失败，错误代码：" << GetLastError() << std::endl;
        return 0;
    }

    // 解析 URL  
    URL_COMPONENTSA urlComponents = { 0 };
    urlComponents.dwStructSize = sizeof(urlComponents);
    char hostName[256] = { 0 };
    char urlPath[1024] = { 0 };
    urlComponents.lpszHostName = hostName;
    urlComponents.dwHostNameLength = sizeof(hostName);
    urlComponents.lpszUrlPath = urlPath;
    urlComponents.dwUrlPathLength = sizeof(urlPath);

    if (!InternetCrackUrlA(fullUrl.c_str(), 0, 0, &urlComponents)) {
        InternetCloseHandle(hInternet);
        return 0;
    }

    // 建立连接  
    HINTERNET hConnect = InternetConnectA(hInternet, hostName, urlComponents.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        //std::cerr << "InternetConnect 失败，错误代码：" << GetLastError() << std::endl;
        InternetCloseHandle(hInternet);
        return 0;
    }

    //  打开请求  

   // const char* acceptTypes[] = {"*/*", NULL};
    /*
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", urlComponents.lpszUrlPath, NULL, NULL, acceptTypes, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        //std::cerr << "HttpOpenRequest 失败，错误代码：" << GetLastError() << std::endl;
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }
    */

    // 打开请求，使用 GET 方法  
    const char* acceptTypes[] = { "*/*", NULL };
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "GET", urlComponents.lpszUrlPath, NULL, NULL, acceptTypes, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }

    // 设置请求头  
    //std::string headers = "Content-Type: application/x-www-form-urlencoded";
    // 设置请求头  
    std::string headers = "User-Agent: Mozilla/5.0\r\n";
    headers += "Accept: */*\r\n";
    headers += "Connection: Keep-Alive\r\n";
    if (!HttpAddRequestHeadersA(hRequest, headers.c_str(), -1, HTTP_ADDREQ_FLAG_ADD))
    {
        std::cerr << "HttpAddRequestHeadersA 失败，错误代码: " << GetLastError() << std::endl;
    }

    // 发送请求，不发送请求体  
    BOOL bResult = HttpSendRequestA(hRequest, NULL, 0, NULL, 0);
    if (!bResult) {
        std::cerr << "HttpSendRequest 失败，错误代码：" << GetLastError() << std::endl;
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return 0;
    }

    // 检查HTTP状态码  
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusCodeSize, NULL))
    {
        if (statusCode != 200)
        {
            std::cerr << "HTTP 请求失败，状态码: " << statusCode << std::endl;
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            return 0;
        }
    }
    else
    {
        std::cerr << "无法获取 HTTP 状态码。" << std::endl;
    }

    // 读取服务器响应（可选）  
    char buffer[1024];
    DWORD bytesRead = 0;
    std::string response;

    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        //buffer[bytesRead] = '\0';
        response.append(buffer, bytesRead);
        bytesRead = 0;
    }

    // 将 UTF-8 编码的字符串转换为宽字符字符串（UTF-16）  
    int wideCharLength = MultiByteToWideChar(CP_UTF8, 0, response.c_str(), static_cast<int>(response.length()), NULL, 0);
    if (wideCharLength > 0) {
        std::wstring wideResponse(wideCharLength, 0);
        MultiByteToWideChar(CP_UTF8, 0, response.c_str(), static_cast<int>(response.length()), &wideResponse[0], wideCharLength);
        // 提取 JSON 数据  
        size_t startPos = wideResponse.find(L'(');
        size_t endPos = wideResponse.rfind(L')');

        if (startPos != std::wstring::npos && endPos != std::wstring::npos && startPos < endPos) {
            std::wstring jsonWString = wideResponse.substr(startPos + 1, endPos - startPos - 1);

            // 转换为 UTF-8 编码的字符串供 JSON 解析  
            int utf8Length = WideCharToMultiByte(CP_UTF8, 0, jsonWString.c_str(), -1, NULL, 0, NULL, NULL);
            if (utf8Length > 0) {
                std::string jsonString(utf8Length - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, jsonWString.c_str(), -1, &jsonString[0], utf8Length, NULL, NULL);

                // 解析 JSON 数据  
                try {
                    json jsonData = json::parse(jsonString);

                    int result = jsonData.value("result", -1);
                    std::string msg = jsonData.value("msg", "");
                    int ret_code = jsonData.value("ret_code", -1);

                    //std::cout << "result: " << result << std::endl;
                    //std::cout << "msg: " << msg << std::endl;
                    //std::cout << "ret_code: " << ret_code << std::endl;



                    OutputDebugStringW(L"服务器响应：");
                    OutputDebugStringW(wideResponse.c_str());
                    if (result == 1)
                    {
                        return 666;
                    }
                    else
                    {
                        return 0;
                    }

                }
                catch (const json::parse_error& e) {
                    //std::cerr << "JSON 解析错误：" << e.what() << std::endl;
                    return 0;
                }
            }
            else {
                std::cerr << "宽字符转换为 UTF-8 编码字符串失败。" << std::endl;
                return 0;
            }
        }
        else {
            std::wcerr << L"无法提取 JSON 数据。" << std::endl;
            return 0;
        }
        // 输出宽字符字符串  
        //std::wcout.imbue(std::locale("chs")); // 设置控制台使用中文区域设置  

        //std::wcout << L"服务器响应：" << wideResponse << std::endl;
        // 使用 OutputDebugStringW 输出宽字符串  
        OutputDebugStringW(L"服务器响应：");
        OutputDebugStringW(wideResponse.c_str());

        // 提取 JSON 数据（如果需要处理 JSON）  
        // 可以使用宽字符版本的字符串进行后续处理  

    }
    else {
        // 转换失败，输出错误信息  
        //std::cerr << "无法将服务器响应从 UTF-8 转换为宽字符字符串，错误代码：" << GetLastError() << std::endl;
    }

    // 输出服务器响应（可根据需要进行解析）  
    //std::cout << "服务器响应：" << response << std::endl;
    //std::cout << "服务器响应原始数据：" << response << std::endl

    // 提取 JSON 数据  


    // 清理资源  
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);


}

std::string GetLastErrorAsString()
{
    //Get the error message ID, if any.
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0) {
        return std::string(); //No error message has been recorded
    }

    LPSTR messageBuffer = nullptr;

    //Ask Win32 to give us the string version of that message ID.
    //The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    //Copy the error message into a std::string.
    std::string message(messageBuffer, size);

    //Free the Win32's string's buffer.
    LocalFree(messageBuffer);

    return message;
}




// 全局变量:
HINSTANCE hInst;                                // 当前实例
WCHAR szTitle[100];                  // 标题栏文本
WCHAR szWindowClass[MAX_LOADSTRING];            // 主窗口类名
HWND hwndButton;
HWND hwndButton1;
HWND hEdit;
HWND hStatic;
HWND hEdit1;
HWND hStatic1;
HWND hStatic2;
HWND hStatic3;
HWND hStatic4;
HWND hStatic5;
HWND hComboBox; 
HWND hCheckBox;
HWND hCheckBox2;
UINT_PTR timerId;
NOTIFYICONDATA g_nid; // 托盘图标数据  
// 菜单句柄  
HMENU hMenu;
// 获取用户名和密码  
std::string username;
std::string password;
//状态


// 此代码模块中包含的函数的前向声明:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: 在此处放置代码

    
    //检查配置文件是否存在，若不存在建立配置文件
    //刷新配置并运行
    // 获取程序执行路径
    TCHAR szPath[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, szPath, MAX_PATH);
    //PathRemoveFileSpec(szPath); // 去掉文件名，只保留路径

    // 文件路径
    wchar_t buffer[MAX_PATH + 1] = { 0 };
    GetCurrentDirectory(MAX_PATH, buffer);
    OutputDebugString(buffer);
    OutputDebugString(L"\n");
    GetModuleFileName(NULL, buffer, MAX_PATH);
    OutputDebugString(buffer);
    OutputDebugString(L"\n");
    PathRemoveFileSpec(buffer);
    OutputDebugString(buffer);
    OutputDebugString(L"\n");

    // 构造配置文件路径
    
    _tcscpy_s(szConfigFile, MAX_PATH, szPath);
    PathRemoveFileSpec(szConfigFile);
    _tcscat_s(szConfigFile, MAX_PATH, TEXT("\\"));
    _tcscat_s(szConfigFile, MAX_PATH, TEXT("setting"));
    OutputDebugString(szConfigFile);

    //建立配置文件
    HANDLE filopen=CreateFile(
        szConfigFile,
        GENERIC_WRITE,
        FILE_SHARE_WRITE,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    
    
    //std::wstring szzTitle = L"Hello — こんにちは — 你好！— 🔥💧";
    //输出错误代码
    WCHAR inputt[512];
    DWORD shenm = GetLastError();
    std::wstring szzTitle = String2Wstring(GetLastErrorAsString());
    LPCWSTR sw = szzTitle.c_str();
    wsprintf(inputt,sw);
    OutputDebugString(inputt);

    //初始化完成
    wsprintf(inputt, L"初始化完成\n");
    OutputDebugString(inputt);


    // 打开配置文件  
    std::ifstream configFile(szConfigFile);
    //configFile.is_open();
    //configFile.is_open();
    if (!configFile.is_open()) {
        OutputDebugString(L"无法打开配置文件");
        //return -1;
    }
    // 读取并解析 JSON 配置文件  
    json configData;
    try {
        if (configFile.peek() == std::ifstream::traits_type::eof()) {
            // 文件为空，写入默认配置  
            configFile.close();

            WriteDefaultConfig(szConfigFile);
        }
        else {
            configFile >> configData;
            //根据配置文件初始化参数
        }
    }
    catch (const json::parse_error& e) {
        OutputDebugString(L"解析配置文件时出错");
    }

    configFile.close();


    //设置更新函数，更新用量和状态
    
    // 获取用户名和密码  
    username = configData["username"].get<std::string>();
    password = configData["password"].get<std::string>();
    //获取状态
    auto_connect= configData["auto_connect"].get<bool>();
    auto_start = configData["auto_start"].get<bool>();
    //status
    
    


    // 检查配置文件是否存在
   /* if (!PathFileExistsW(szConfigFile))
    {
        // 创建配置文件
        HANDLE hFile = CreateFile(szConfigFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            // 在这里写入默认配置信息
            // ...
            CloseHandle(hFile);
        }
        else
        {
            // 创建配置文件失败，处理错误
        }
    }*/


    // 初始化全局字符串
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_AUTOCONNECT, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // 执行应用程序初始化:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }
    WCHAR input[512];
    wsprintf(input,L"初始化完成\n");
    OutputDebugString(input);

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_AUTOCONNECT));

    MSG msg;

    // 主消息循环:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

DWORD WINAPI NetworkThreadProc(LPVOID lpParameter) {
    HWND hwnd = (HWND)lpParameter;

    //status = LoginCampusNetwork(username, password);
    // 执行网络操作的函数
    // 使用读取的用户名和密码进行登录 
    status = LoginCampusNetwork(username, password);
    if (status == 666) {
        //登陆成功
        OutputDebugString(L"Successfully connected!");
        SetWindowText(hStatic2, L"状态：已登录");
        ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：已登录");
    }
    else if (status == 0)
    {
        //连接失败
        OutputDebugString(L"Connection failed.");
        SetWindowText(hStatic2, L"状态：连接失败");
        ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：连接失败");
    }
    else if (status == 1)
    {
        //账号密码错误
        status = LoginCampusNetwork(username, password);
        SetWindowText(hStatic2, L"状态：账号密码错误");
        ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：账号密码错误");
    }
    else if (status == 2)
    {
        SetWindowText(hStatic2, L"状态：已登录");
        ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：已登录");
        //已经登录
    }
    PostMessage(hwnd, WM_USER + 1, 0, (LPARAM)L"Network operation failed");
    PostMessage(hwnd, WM_USER + 2, 0, 0);
    return 0;
}

DWORD WINAPI NetworkThreadProc2(LPVOID lpParameter) {
    HWND hwnd = (HWND)lpParameter;

    //status = LoginCampusNetwork(username, password);
    // 执行网络操作的函数
    // 使用读取的用户名和密码进行登录 
    status = LogoutCampusNetwork(username, password);
    if (status == 666) {
        //登出成功
        OutputDebugString(L"Successfully connected!");
        SetWindowText(hStatic2, L"状态：已登录");
        ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：已登录");
    }
    else if (status == 0)
    {
        //连接失败
        OutputDebugString(L"Connection failed.");
        SetWindowText(hStatic2, L"状态：连接失败");
        ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：连接失败");
    }
    //PostMessage(hwnd, WM_USER + 3, 0, (LPARAM)L"Network operation failed");
    //PostMessage(hwnd, WM_USER + 4, 0, 0);
    return 0;
}

//
//  函数: MyRegisterClass()
//
//  目标: 注册窗口类。
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_AUTOCONNECT);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_ICON1));

    return RegisterClassExW(&wcex);
}

//
//   函数: InitInstance(HINSTANCE, int)
//
//   目标: 保存实例句柄并创建主窗口
//
//   注释:
//
//        在此函数中，我们在全局变量中保存实例句柄并
//        创建和显示主程序窗口。
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // 将实例句柄存储在全局变量中

   HWND hWnd = CreateWindowW(szWindowClass,L"什么？", WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, 600,800 , nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);
   //绘制基本控件
   if(auto_connect==1)
   {
       timerId = SetTimer(hWnd, TIMER_ID, 10000, NULL); // 设置初始定时器
   }
   
   //保存键
   hwndButton = CreateWindow(
       L"BUTTON",  // Predefined class; Unicode assumed 
       L"保存",      // Button text 
       WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,  // Styles 
       10,         // x position 
       10,         // y position 
       90,        // Button width
       50,        // Button height
       hWnd,     // Parent window
       NULL,       // No menu.
       (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE),
       NULL);      // Pointer not needed.
   // 创建选框（复选框）  
   hCheckBox = CreateWindowEx(
       0, L"BUTTON", L"开机自动启动", // 控件类型和初始文本  
       WS_CHILD | WS_VISIBLE | BS_CHECKBOX, // 控件样式  
       10, 128, 138, 20, // 位置和大小  
       hWnd, // 父窗口句柄  
       NULL, // 菜单句柄  
       hInstance, // 实例句柄  
       NULL // 附加参数  
   );
   if (auto_start == false)
   {
       SendMessage(hCheckBox, BM_SETCHECK, BST_UNCHECKED, 0);
   }
   else
   {
       SendMessage(hCheckBox, BM_SETCHECK, BST_CHECKED, 0);
   }
   // 创建选框（复选框）  
   hCheckBox2 = CreateWindowEx(
       0, L"BUTTON", L"自动登录", // 控件类型和初始文本  
       WS_CHILD | WS_VISIBLE | BS_CHECKBOX, // 控件样式  
       10, 148, 138, 20, // 位置和大小  
       hWnd, // 父窗口句柄  
       NULL, // 菜单句柄  
       hInstance, // 实例句柄  
       NULL // 附加参数  
   );
   if (auto_connect==false) 
   {
       SendMessage(hCheckBox2, BM_SETCHECK, BST_UNCHECKED, 0);
   }
   else 
   {
       SendMessage(hCheckBox2, BM_SETCHECK, BST_CHECKED, 0);
   }
   //确认
   hwndButton1 = CreateWindow(
       L"BUTTON",  // Predefined class; Unicode assumed 
       L"退出登录",      // Button text 
       WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,  // Styles 
       10,         // x position 
       68,         // y position 
       90,        // Button width
       50,        // Button height
       hWnd,     // Parent window
       NULL,       // No menu.
       (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE),
       NULL);      // Pointer not needed.
   // 创建一个静态文本控件  
   hStatic = CreateWindowEx(
       0, L"STATIC",   // Predefined class; Unicode assumed   
       L"账号:",   // Static text  
       WS_CHILD | WS_VISIBLE, // Styles   
       110, 10, 80, 25,        // x, y, width, height  
       hWnd,        // Parent window  
       NULL,        // No menu  
       (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE),
       NULL);       // Pointer not needed
   // 创建一个编辑控件  
   hEdit = CreateWindowEx(
       0, L"EDIT",   // Predefined class; Unicode assumed   
       NULL,         // No window title   
       WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT, // Styles   
       150, 7, 200, 25,        // x, y, width, height  
       hWnd,        // Parent window  
       NULL,        // No menu  
       (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE),
       NULL);       // Pointer not needed 
   // 创建一个静态文本控件  
   hStatic1 = CreateWindowEx(
       0, L"STATIC",   // Predefined class; Unicode assumed   
       L"密码:",   // Static text  
       WS_CHILD | WS_VISIBLE, // Styles   
       110, 40, 80, 25,        // x, y, width, height  
       hWnd,        // Parent window  
       NULL,        // No menu  
       (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE),
       NULL);       // Pointer not needed

   


   // 创建静态文本控件  
   hStatic2 = CreateWindowEx(
       0, L"STATIC", L"状态：-", // 控件类型和初始文本  
       WS_CHILD | WS_VISIBLE | SS_LEFT, // 控件样式  
       110, 70, 180, 20, // 位置和大小  
       hWnd, // 父窗口句柄  
       NULL, // 菜单句柄  
       hInstance, // 实例句柄  
       NULL // 附加参数  
   );
   

   // 创建静态文本控件  
   hStatic3 = CreateWindowEx(
       0, L"STATIC", L"已用流量：", // 控件类型和初始文本  
       WS_CHILD | WS_VISIBLE | SS_LEFT, // 控件样式  
       110, 100, 180, 20, // 位置和大小  
       hWnd, // 父窗口句柄  
       NULL, // 菜单句柄  
       hInstance, // 实例句柄  
       NULL // 附加参数  
   );
   // 创建静态文本控件  
   hStatic4 = CreateWindowEx(
       0, L"STATIC", L"180301.780", // 控件类型和初始文本  
       WS_CHILD | WS_VISIBLE | SS_LEFT, // 控件样式  
       188, 100, 80, 20, // 位置和大小  
       hWnd, // 父窗口句柄  
       NULL, // 菜单句柄  
       hInstance, // 实例句柄  
       NULL // 附加参数  
   );
   // 创建下拉选框（组合框）  
   hComboBox = CreateWindowEx(
       0, L"COMBOBOX", NULL, // 控件类型  
       WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, // 控件样式  
       280, 98, 48, 100, // 位置和大小  
       hWnd, // 父窗口句柄  
       NULL, // 菜单句柄  
       hInstance, // 实例句柄  
       NULL // 附加参数  
   );
   // 添加选项到组合框  
   SendMessage(hComboBox, CB_ADDSTRING, 0, (LPARAM)L"GB");
   SendMessage(hComboBox, CB_ADDSTRING, 0, (LPARAM)L"MB");
   SendMessage(hComboBox, CB_ADDSTRING, 0, (LPARAM)L"KB");

   // 设置默认选中项（可选）  
   SendMessage(hComboBox, CB_SETCURSEL, 0, 0); // 选择第一个选项 
   // 显示窗口  
   //ShowWindow(hStatic2, SW_SHOW);
   //UpdateWindow(hStatic2);
   // 创建一个编辑控件  
   hEdit1 = CreateWindowEx(
       0, L"EDIT",   // Predefined class; Unicode assumed   
       NULL,         // No window title   
       WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT, // Styles   
       150, 33, 200, 25,        // x, y, width, height  
       hWnd,        // Parent window  
       NULL,        // No menu  
       (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE),
       NULL);       // Pointer not needed 

   //初始化输入框字符
   // 将 std::string 转换为 std::wstring  
   std::wstring wInputText(username.begin(), username.end());
   // 设置编辑控件的文本  
   SetWindowText(hEdit, wInputText.c_str()); // 使用 c_str() 获取宽字符字符串
   // 将 password 转换为 std::wstring  
   std::wstring wInputPassword(password.begin(), password.end());
   // 设置密码输入框的文本  
   SetWindowText(hEdit1, wInputPassword.c_str()); // 假设 hEditPassword 是密码输入框的句柄
   // 设置输入框为密码样式  
   SendMessage(hEdit1, EM_SETPASSWORDCHAR, '$', 0); // 使用 '*' 作为密码字符


   // 初始化托盘图标数据  
   g_nid.cbSize = sizeof(NOTIFYICONDATA);
   g_nid.hWnd = hWnd;
   g_nid.uID = 1;
   g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
   g_nid.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1)); // 加载图标 
   g_nid.uCallbackMessage = WM_TRAYICON;
   lstrcpy(g_nid.szTip, L"BJUT"); // 托盘提示文本  

   // 添加托盘图标  
   Shell_NotifyIcon(NIM_ADD, &g_nid);
   // 创建右键菜单  
   hMenu = CreatePopupMenu();
   AppendMenu(hMenu, MF_STRING, 1, L"用量：");
   AppendMenu(hMenu, MF_STRING, 2, L"状态：");
   AppendMenu(hMenu, MF_STRING, 3, L"退出登录");
   AppendMenu(hMenu, MF_STRING, 4, L"退出");

   // 创建一个新线程来执行网络操作  
   CreateThread(NULL, 0, NetworkThreadProc, (LPVOID)hWnd, 0, NULL);

   HICON hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
   SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
   SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
   
   /*// 使用读取的用户名和密码进行登录 
   status = LoginCampusNetwork(username, password);
   if (status == 666) {
       //登陆成功
       OutputDebugString(L"Successfully connected!");
       SetWindowText(hStatic2, L"状态：已登录");
       ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：已登录");
   }
   else if (status == 0)
   {
       //连接失败
       OutputDebugString(L"Connection failed.");
       SetWindowText(hStatic2, L"状态：连接失败");
       ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：连接失败");
   }
   else if (status == 1)
   {
       //账号密码错误
       status = LoginCampusNetwork(username, password);
       SetWindowText(hStatic2, L"状态：账号密码错误");
       ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：账号密码错误");
   }
   else if (status == 2)
   {
       SetWindowText(hStatic2, L"状态：已登录");
       ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：已登录");
       //已经登录
   }*/
   //SetWindowText(hwndButton1, L"退出登录");


   return TRUE;
}

//
//  函数: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  目标: 处理主窗口的消息。
//
//  WM_COMMAND  - 处理应用程序菜单
//  WM_PAINT    - 绘制主窗口
//  WM_DESTROY  - 发送退出消息并返回
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    static HBRUSH hBrush = NULL;
    MINMAXINFO* mmi = (MINMAXINFO*)lParam;
    RECT rect;
    switch (message)
    {
    case WM_TIMER:
        if (wParam == TIMER_ID) { // 检查定时器 ID  
            //std::cout << "定时器到期!" << std::endl; // 处理定时器到期事件  
            OutputDebugString(L"定时器到期!");
            // 创建一个新线程来执行网络操作  
            CreateThread(NULL, 0, NetworkThreadProc, (LPVOID)hWnd, 0, NULL);
            /*status = LoginCampusNetwork(username, password);
            if (status == 666) {
                //登陆成功
                OutputDebugString(L"Successfully connected!");
                SetWindowText(hStatic2, L"状态：已登录");
                ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：已登录");
            }
            else if (status == 0)
            {
                //连接失败
                OutputDebugString(L"Connection failed.");
                SetWindowText(hStatic2, L"状态：连接失败");
                ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：连接失败");
            }
            else if (status == 1)
            {
                //账号密码错误
                SetWindowText(hStatic2, L"状态：账号密码错误");
                ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：账号密码错误");
                //status = LoginCampusNetwork(username, password);
            }
            else if (status == 2)
            {
                //已经登录
                OutputDebugString(L"已经登陆");
                SetWindowText(hStatic2, L"状态：已登录");
                ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：已登录");
            }*/
            // 这里可以调用函数改变定时器的间隔  
            //KillTimer(hWnd, TIMER_ID); // 停止现有定时器  
            //timerId = SetTimer(hWnd, TIMER_ID, 1000, NULL); // 创建新的定时器  
            //std::cout << "定时器间隔已更改为 2 秒." << std::endl;
        }
        break;
    case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
                case 1: // 用量 
                    //MessageBox(hWnd, L"退出登录功能未实现", L"提示", MB_OK);
                    ModifyMenu(hMenu, 2, MF_BYPOSITION | MF_STRING, 2, L"已使用流量: 10 MB");
                    //UpdateMenuItem(3, L"已使用流量: 10 MB"); // 假设更新为 10 MB
                    //MessageBox(hWnd, L"已使用流量功能未实现", L"提示", MB_OK);
                    break;
                case 2: // 状态  
                    //MessageBox(hWnd, L"连接功能未实现", L"提示", MB_OK);
                    //ModifyMenu(hMenu, 2, MF_BYPOSITION | MF_STRING, 2, L"已使用流量: 10 MB");
                    break;
                case 3: // 退出登录
                    SendMessage(hwndButton1,BM_CLICK, 0, 0);
                    break;
                case 4: // 退出
                    // 清理资源  
                    KillTimer(hWnd, TIMER_ID); // 清理定时器
                    PostQuitMessage(0);
                    break;
            }
            int wmId = LOWORD(wParam);
            // 检查是否是下拉框选项改变事件  
            if (HIWORD(wParam) == CBN_SELCHANGE)
            {
                // 获取当前选中的选项  
                int index = SendMessage(hComboBox, CB_GETCURSEL, 0, 0);
                wchar_t buffer[100];
                SendMessage(hComboBox, CB_GETLBTEXT, index, (LPARAM)buffer);

                // 将选中的选项转换为 std::string  
                selectedOption = WideStringToString(buffer);
                OutputDebugString(buffer); // 输出选中的选项
                //更改单位后输出

            }
            // 检查是否是编辑框控件的句柄
            // 检查句柄而不是 ID  
            // 检查是否是文本变化事件  
            if (HIWORD(wParam) == EN_CHANGE)
            {
                if((HWND)lParam == hEdit)
                {
                    wchar_t usernameBuffer[100];
                    // 获取用户名和密码输入框的内容  
                    GetWindowText(hEdit, usernameBuffer, 100);
                    // 将 wchar_t 数组转换为 std::wstring  
                    std::wstring usernameW(usernameBuffer);
                    // 将 std::wstring 转换为 std::string  
                    username = WideStringToString(usernameW);
                    // 读取现有的 JSON 配置文件  
                    std::ifstream inputFile(szConfigFile);
                    json config;
                    if (inputFile.is_open()) {
                        inputFile >> config;
                        inputFile.close();
                    }

                    // 更新配置项  
                    config["username"] = username; //更新配置项  

                    // 写回 JSON 配置文件  
                    std::ofstream outputFile(szConfigFile);
                    if (outputFile.is_open()) {
                        outputFile << config.dump(4); // 以 4 个空格缩进格式化输出  
                        outputFile.close();
                        OutputDebugString(L"已写入默认配置到文件");
                    }



                }else
                {
                    wchar_t passwordBuffer[100];
                    GetWindowText(hEdit1, passwordBuffer, 100);
                    std::wstring passwordW(passwordBuffer);
                    password = WideStringToString(passwordW);
                    // 读取现有的 JSON 配置文件  
                    std::ifstream inputFile(szConfigFile);
                    json config;
                    if (inputFile.is_open()) {
                        inputFile >> config;
                        inputFile.close();
                    }

                    // 更新配置项  
                    config["password"] = password; //更新配置项  

                    // 写回 JSON 配置文件  
                    std::ofstream outputFile(szConfigFile);
                    if (outputFile.is_open()) {
                        outputFile << config.dump(4); // 以 4 个空格缩进格式化输出  
                        outputFile.close();
                        OutputDebugString(L"已写入默认配置到文件");
                    }
                }
                //OutputDebugString(L"？？？？？？？？？？");
                
                
            }
            // 检查是否是复选框的点击事件  自启动
            if (LOWORD(wParam) == BN_CLICKED && (HWND)lParam == hCheckBox) {
                // 获取复选框的当前状态  
                BOOL isChecked = SendMessage(hCheckBox, BM_GETCHECK, 0, 0);
                // 切换复选框的状态  
                if (isChecked == BST_CHECKED) {
                    SendMessage(hCheckBox, BM_SETCHECK, BST_UNCHECKED, 0);
                    //取消开机自动启动
                    SetAutoStart(false);
                    UpdateConfigFile(false);
                }
                else {
                    SendMessage(hCheckBox, BM_SETCHECK, BST_CHECKED, 0);
                    //开机自动启动
                    SetAutoStart(true);
                    UpdateConfigFile(true);
                }
            }
            // 检查是否是复选框的点击事件  自动登录
            if (LOWORD(wParam) == BN_CLICKED && (HWND)lParam == hCheckBox2) {
                // 获取复选框的当前状态  
                BOOL isChecked = SendMessage(hCheckBox2, BM_GETCHECK, 0, 0);
                // 切换复选框的状态  
                if (isChecked == BST_CHECKED) {
                    SendMessage(hCheckBox2, BM_SETCHECK, BST_UNCHECKED, 0);
                    //设置没有自动登录
                    auto_connect =false;
                    KillTimer(hWnd, TIMER_ID); // 停止现有定时器
                    // 读取现有的 JSON 配置文件  
                    std::ifstream inputFile(szConfigFile);
                    json config;
                    if (inputFile.is_open()) {
                        inputFile >> config;
                        inputFile.close();
                    }

                    // 更新配置项  
                    config["auto_connect"] = false; // 假设你要更新的配置项为 "auto_start"  

                    // 写回 JSON 配置文件  
                    std::ofstream outputFile(szConfigFile);
                    if (outputFile.is_open()) {
                        outputFile << config.dump(4); // 以 4 个空格缩进格式化输出  
                        outputFile.close();
                    }
                }
                else {
                    SendMessage(hCheckBox2, BM_SETCHECK, BST_CHECKED, 0);
                    //设置有自动登录
                    auto_connect =true;
                    timerId = SetTimer(hWnd, TIMER_ID, 10000, NULL); // 设置初始定时器
                    // 读取现有的 JSON 配置文件  
                    std::ifstream inputFile(szConfigFile);
                    json config;
                    if (inputFile.is_open()) {
                        inputFile >> config;
                        inputFile.close();
                    }

                    // 更新配置项  
                    config["auto_connect"] = true; // 假设你要更新的配置项为 "auto_start"  

                    // 写回 JSON 配置文件  
                    std::ofstream outputFile(szConfigFile);
                    if (outputFile.is_open()) {
                        outputFile << config.dump(4); // 以 4 个空格缩进格式化输出  
                        outputFile.close();
                        OutputDebugString(L"已写入默认配置到文件");
                    }
                }
            }
            // 分析菜单选择:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                //ShowWindow(hWnd, SW_HIDE); // 隐藏窗口而不是销毁
                Shell_NotifyIcon(NIM_DELETE, &g_nid); // 删除托盘图标
                DestroyWindow(hWnd);
                break;
            case IDC_SAVE:
                WCHAR input2[512];
                wsprintf(input2, L"按钮点击\n");
                OutputDebugString(input2);
                break;

            case BN_CLICKED:
                //printf("行");
                WCHAR input[512];
                wsprintf(input, L"按钮点击\n");
                OutputDebugString(input);
                //int a = LOWORD(wParam);
                //int b = GetWindowLongPtr(hwndButton1, GWLP_ID);
                if ((HWND)lParam == hwndButton)
                {
                    wsprintf(input, L"登录:%d\n", 100);
                    OutputDebugString(input);
                    //更改配置信息
                    // 创建一个新线程来执行网络操作  
                    CreateThread(NULL, 0, NetworkThreadProc, (LPVOID)hWnd, 0, NULL);
                    /*// 使用读取的用户名和密码进行登录 
                    status = LoginCampusNetwork(username, password);
                    if (status == 666) {
                        //登陆成功
                        OutputDebugString(L"Successfully connected!");
                        SetWindowText(hStatic2, L"状态：已登录");
                        ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：已登录");
                    }
                    else if (status == 0)
                    {
                        //连接失败
                        OutputDebugString(L"Connection failed.");
                        SetWindowText(hStatic2, L"状态：连接失败");
                        ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：连接失败");
                    }
                    else if (status == 1)
                    {
                        //账号密码错误
                        status = LoginCampusNetwork(username, password);
                        SetWindowText(hStatic2, L"状态：账号密码错误");
                        ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：账号密码错误");
                    }
                    else if (status == 2)
                    {
                        SetWindowText(hStatic2, L"状态：已登录");
                        ModifyMenu(hMenu, 1, MF_BYPOSITION | MF_STRING, 1, L"状态：已登录");
                        //已经登录
                    }*/
                    //刷新配置
                }
                else if((HWND)lParam == hwndButton1)
                {
                    wsprintf(input, L"退出登录:%d\n", 200);
                    OutputDebugString(input);
                    //更改配置信息
                    // 创建一个新线程来执行网络操作  
                    CreateThread(NULL, 0, NetworkThreadProc2, (LPVOID)hWnd, 0, NULL);
                    SendMessage(hCheckBox2, BM_SETCHECK, BST_UNCHECKED, 0);
                    //设置没有自动登录
                    auto_connect = false;
                    KillTimer(hWnd, TIMER_ID); // 停止现有定时器
                    // 读取现有的 JSON 配置文件  
                    std::ifstream inputFile(szConfigFile);
                    json config;
                    if (inputFile.is_open()) {
                        inputFile >> config;
                        inputFile.close();
                    }

                    // 更新配置项  
                    config["auto_connect"] = false; // 假设你要更新的配置项为 "auto_start"  

                    // 写回 JSON 配置文件  
                    std::ofstream outputFile(szConfigFile);
                    if (outputFile.is_open()) {
                        outputFile << config.dump(4); // 以 4 个空格缩进格式化输出  
                        outputFile.close();
                    }
                    //刷新配置
                }
                //TCHAR buffer[100];
                //_stprintf_s(buffer, _countof(buffer), _T("wparam:0x%lx, lparam:0x%lx\n"), wParam, lParam);
                //OutputDebugString(buffer);
                //TRACE("%s","no error, no warning");
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: 在此处添加使用 hdc 的任何绘图代码...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_CTLCOLORSTATIC:
        {
        HDC hdcStatic = (HDC)wParam;
        SetBkMode(hdcStatic, TRANSPARENT); // 设置背景模式为透明  
        if (!hBrush) {
            hBrush = CreateSolidBrush(GetSysColor(COLOR_WINDOW)); // 创建一个与窗口背景颜色相同的画刷  
        }
        return (INT_PTR)hBrush;
        }
    case WM_TRAYICON:
        if (lParam == WM_LBUTTONDBLCLK) // 双击托盘图标  
        {
            ShowWindow(hWnd, SW_RESTORE); // 恢复窗口  
            SetForegroundWindow(hWnd); // 设置为前景窗口  
        }
        if (lParam == WM_RBUTTONDOWN) // 右键点击托盘图标  
        {
            POINT cursorPos;
            GetCursorPos(&cursorPos); // 获取鼠标位置  
            SetForegroundWindow(hWnd); // 确保窗口在前景  
            TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, cursorPos.x, cursorPos.y, 0, hWnd, NULL);
        }
        break;
    case WM_CLOSE:
        ShowWindow(hWnd, SW_HIDE); // 隐藏窗口而不是销毁  
        return 0;
    
    case WM_DESTROY:
        Shell_NotifyIcon(NIM_DELETE, &g_nid); // 删除托盘图标
        KillTimer(hWnd, TIMER_ID); // 清理定时器
        PostQuitMessage(0);
        break;
    case WM_SIZE: 
        // 如果窗口大小发生变化，则将其恢复到指定大小
        //GetWindowRect(hWnd, &rect);
        //SetWindowPos(hWnd, NULL, rect.left, rect.top, 800, 600, SWP_NOZORDER | SWP_NOACTIVATE);
        break;
    case WM_GETMINMAXINFO:
        mmi->ptMaxTrackSize.x = 380; // 最大宽度
        mmi->ptMaxTrackSize.y = 280; // 最大高度
        mmi->ptMinTrackSize.x = 380; // 最小宽度
        mmi->ptMinTrackSize.y = 280; // 最小高度
        break;
    case WM_CREATE:
        return 0;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// “关于”框的消息处理程序。
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        // 设置初始文本  
        SetDlgItemText(hDlg, IDC_EDIT_EMAIL, L"whatiname@emails.bjut.edu.cn");
        return (INT_PTR)TRUE;


    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}