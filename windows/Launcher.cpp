// Native Windows host for the same interface embedded by macos/Launcher.swift.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wrl.h>
#include <WebView2.h>
#include <atomic>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;
namespace fs = std::filesystem;

namespace {
constexpr wchar_t WindowClass[] = L"Rustorrent.Desktop.Window";
constexpr UINT TrayMessage = WM_APP + 1;
constexpr UINT QuitMessage = WM_APP + 2;
enum : UINT { Add = 100, Downloads, Reload, Settings, Hide, Show, Exit, About };

struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle() = default;
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};

void Check(HRESULT result, const char* operation) {
    if (FAILED(result)) throw std::runtime_error(operation);
}

std::wstring Wide(const std::string& value) {
    int length = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring out(length, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), length);
    return out;
}

std::string Utf8(const std::wstring& value) {
    int length = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    std::string out(length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), length, nullptr, nullptr);
    return out;
}

// Quote one argument according to CommandLineToArgvW / the CRT parsing rules.
std::wstring Quote(const std::wstring& value) {
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : value) {
        if (c == L'\\') { ++slashes; continue; }
        out.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\');
        slashes = 0;
        out += c;
    }
    out.append(slashes * 2, L'\\');
    return out + L"\"";
}

bool LocalUrl(const std::wstring& url, const std::wstring& origin) {
    return url == origin || url.compare(0, origin.size() + 1, origin + L"/") == 0;
}

bool ExternalUrl(const std::wstring& url) {
    return url.compare(0, 8, L"https://") == 0 || url.compare(0, 7, L"http://") == 0;
}

fs::path KnownFolder(REFKNOWNFOLDERID id) {
    PWSTR path = nullptr;
    Check(SHGetKnownFolderPath(id, 0, nullptr, &path), "Could not locate the user folder.");
    fs::path result(path);
    CoTaskMemFree(path);
    return result;
}

std::wstring Secret() {
    unsigned char bytes[32];
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        throw std::runtime_error("Could not generate a private engine identity.");
    const wchar_t* hex = L"0123456789abcdef";
    std::wstring result;
    for (auto byte : bytes) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}

// The port is free when checked, but another process can take it before the
// engine binds it; App::Tick then restarts the engine on a fresh port.
unsigned short AvailablePort(bool preferred) {
    SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) throw std::runtime_error("Could not reserve a local port.");
    BOOL exclusive = TRUE;
    setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               reinterpret_cast<const char*>(&exclusive), sizeof(exclusive));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(preferred ? 9473 : 0);
    if (bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        address.sin_port = 0;
        if (bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            closesocket(socket);
            throw std::runtime_error("Could not reserve a local port.");
        }
    }
    int size = sizeof(address);
    int result = getsockname(socket, reinterpret_cast<sockaddr*>(&address), &size);
    closesocket(socket);
    if (result != 0) throw std::runtime_error("Could not read the local port.");
    return ntohs(address.sin_port);
}

// The engine logs why it exited; the last line explains a startup failure.
std::wstring LastLogLine(const fs::path& log) {
    std::ifstream file(log, std::ios::binary | std::ios::ate);
    if (!file) return {};
    const std::streamoff size = file.tellg();
    file.seekg(std::max<std::streamoff>(0, size - 4096));
    std::string line, last;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) last = line;
    }
    return Wide(last);
}

struct HttpHandle {
    HINTERNET value;
    ~HttpHandle() { if (value) WinHttpCloseHandle(value); }
};

HINTERNET OpenProbeSession() {
    HINTERNET session = WinHttpOpen(L"Rustorrent Desktop", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session) WinHttpSetTimeouts(session, 500, 500, 500, 500);
    return session;
}

// A response from some other loopback service must never enter the embedded view.
bool ProvesOwnership(HINTERNET session, unsigned short port, const std::wstring& secret) {
    HttpHandle connection{WinHttpConnect(session, L"127.0.0.1", port, 0)};
    if (!connection.value) return false;
    HttpHandle request{WinHttpOpenRequest(connection.value, L"GET", L"/api-token",
                                          nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0)};
    if (!request.value) return false;
    DWORD disable = WINHTTP_DISABLE_REDIRECTS;
    WinHttpSetOption(request.value, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable));
    if (!WinHttpSendRequest(request.value, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request.value, nullptr)) return false;
    DWORD status = 0, size = sizeof(status);
    if (!WinHttpQueryHeaders(request.value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX) ||
        status != 200) return false;
    std::string body;
    char buffer[1024];
    DWORD read = 0;
    while (WinHttpReadData(request.value, buffer, sizeof(buffer), &read) && read) {
        body.append(buffer, read);
        if (body.size() > 4096) return false;
    }
    const std::string expected = Utf8(secret);
    // The engine produces this compact JSON; fail closed for any other shape.
    const std::string prefix = "{\"token\":\"";
    const std::string suffix = "\",\"owner_secret\":\"" + expected + "\"}";
    if (body.size() != prefix.size() + 32 + suffix.size() ||
        body.compare(0, prefix.size(), prefix) != 0 ||
        body.compare(prefix.size() + 32, suffix.size(), suffix) != 0) return false;
    for (size_t i = prefix.size(); i < prefix.size() + 32; ++i)
        if (!isxdigit(static_cast<unsigned char>(body[i]))) return false;
    return true;
}

struct App {
    HWND window = nullptr;
    HICON icon = nullptr;
    NOTIFYICONDATAW tray{};
    Handle backend, shutdown, instance, self;
    ComPtr<ICoreWebView2Controller> controller;
    ComPtr<ICoreWebView2> view;
    std::thread probe;
    std::atomic<bool> closing{false};
    std::atomic<int> ready{0};
    fs::path data, downloads, executable;
    std::wstring origin, secret;
    unsigned short port = 0;
    ULONGLONG started = 0, closingAt = 0;
    bool navigating = false, loaded = false, smoke = false, testWindow = false, failed = false;
    bool capturePending = false, confirmingForceStop = false;
    int exitCode = 0, restarts = 0;

    ~App() {
        closing = true;
        if (probe.joinable()) probe.join();
        if (shutdown.value) SetEvent(shutdown.value);
        if (backend.value) WaitForSingleObject(backend.value, 20000);
        if (controller) controller->Close();
        if (tray.hWnd) Shell_NotifyIconW(NIM_DELETE, &tray);
    }

    void Fail(const std::wstring& message) {
        if (failed || closing) return;
        failed = true;
        exitCode = 1;
        std::ofstream(data / L"launcher-error.txt") << Utf8(message);
        if (!smoke) MessageBoxW(window, (message + L"\n\nEngine log: " + (data / L"engine.log").wstring()).c_str(),
                               L"Rustorrent", MB_OK | MB_ICONERROR);
        BeginQuit();
    }

    void BeginQuit() {
        if (closing.exchange(true)) return;
        closingAt = GetTickCount64();
        if (shutdown.value) SetEvent(shutdown.value);
        if (controller) controller->put_IsVisible(FALSE);
        SetWindowTextW(window, L"Rustorrent — Saving session…");
        InvalidateRect(window, nullptr, TRUE);
    }

    void StartBackend() {
        secret = Secret();
        shutdown.value = CreateEventW(nullptr, TRUE, FALSE,
                                     (L"Local\\Rustorrent.Shutdown." + secret).c_str());
        if (!shutdown.value || GetLastError() == ERROR_ALREADY_EXISTS)
            throw std::runtime_error("Could not create the engine shutdown event.");
        // The engine inherits this handle and watches it, so it saves and exits if
        // the launcher dies, even before the engine starts watching.
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &self.value,
                             SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, 0))
            throw std::runtime_error("Could not share the launcher process with the engine.");
        LaunchEngine(AvailablePort(true));
    }

    void LaunchEngine(unsigned short enginePort) {
        if (probe.joinable()) probe.join();
        if (backend.value) { CloseHandle(backend.value); backend.value = nullptr; }
        ready = 0;
        // Each engine, including a restarted one, gets the full startup budget.
        started = GetTickCount64();
        port = enginePort;
        origin = L"http://127.0.0.1:" + std::to_wstring(port);
        fs::path engine = executable.parent_path() / L"rustorrent-bin.exe";
        if (!fs::exists(engine)) throw std::runtime_error("rustorrent-bin.exe is missing. Extract the entire ZIP before starting Rustorrent.");
        std::wstring command = Quote(engine.wstring()) + L" --ui --ui-addr 127.0.0.1:" +
            std::to_wstring(port) + L" --download-dir " + Quote(downloads.wstring()) +
            L" --log " + Quote((data / L"engine.log").wstring());
        if (smoke || testWindow) command += L" --no-port-mapping";
        std::vector<std::wstring> entries;
        LPWCH inherited = GetEnvironmentStringsW();
        if (!inherited) throw std::runtime_error("Could not read the process environment.");
        for (const wchar_t* entry = inherited; *entry; entry += wcslen(entry) + 1) {
            if (_wcsnicmp(entry, L"RUSTORRENT_UI_OWNER_SECRET=", wcslen(L"RUSTORRENT_UI_OWNER_SECRET=")) == 0 ||
                _wcsnicmp(entry, L"RUSTORRENT_LAUNCHER_HANDLE=", wcslen(L"RUSTORRENT_LAUNCHER_HANDLE=")) == 0) continue;
            entries.emplace_back(entry);
        }
        FreeEnvironmentStringsW(inherited);
        entries.push_back(L"RUSTORRENT_UI_OWNER_SECRET=" + secret);
        entries.push_back(L"RUSTORRENT_LAUNCHER_HANDLE=" +
                          std::to_wstring(reinterpret_cast<uintptr_t>(self.value)));
        std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
            return _wcsicmp(a.c_str(), b.c_str()) < 0;
        });
        std::vector<wchar_t> environment;
        for (const auto& entry : entries) {
            environment.insert(environment.end(), entry.begin(), entry.end());
            environment.push_back(0);
        }
        environment.push_back(0);
        // Inherit only the launcher process handle.
        SIZE_T attributesSize = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attributesSize);
        std::vector<char> attributes(attributesSize);
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
        if (!InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attributesSize))
            throw std::runtime_error("Could not prepare the engine process.");
        PROCESS_INFORMATION process{};
        const bool launched = UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                       &self.value, sizeof(self.value), nullptr, nullptr) &&
            CreateProcessW(engine.c_str(), command.data(), nullptr, nullptr, TRUE,
                           CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                           environment.data(), data.c_str(), &startup.StartupInfo, &process);
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        if (!launched) throw std::runtime_error("Could not start rustorrent-bin.exe.");
        backend.value = process.hProcess;
        if (smoke || testWindow) std::ofstream(data / L"engine.pid") << process.dwProcessId;
        CloseHandle(process.hThread);
        probe = std::thread([this] {
            HttpHandle session{OpenProbeSession()};
            for (int attempt = 0; session.value && attempt < 100 && !closing; ++attempt) {
                if (WaitForSingleObject(backend.value, 0) == WAIT_OBJECT_0) break;
                if (ProvesOwnership(session.value, port, secret)) { ready = 1; return; }
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            ready = -1;
        });
    }

    void Resize() {
        if (!controller) return;
        RECT bounds{};
        GetClientRect(window, &bounds);
        controller->put_Bounds(bounds);
    }

    void OpenExternal(const std::wstring& url) {
        if (ExternalUrl(url) && !smoke)
            ShellExecuteW(window, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }

    void CreateView() {
        HRESULT result = CreateCoreWebView2EnvironmentWithOptions(nullptr, (data / L"WebView2").c_str(), nullptr,
            Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
                [this](HRESULT hr, ICoreWebView2Environment* environment) -> HRESULT {
                    if (closing) return S_OK;
                    if (FAILED(hr) || !environment) {
                        Fail(L"Microsoft Edge WebView2 Runtime is required. Install it from https://go.microsoft.com/fwlink/p/?LinkId=2124703 and reopen Rustorrent.");
                        return S_OK;
                    }
                    HRESULT create = environment->CreateCoreWebView2Controller(window,
                        Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(
                            [this](HRESULT status, ICoreWebView2Controller* control) -> HRESULT {
                                if (closing) { if (control) control->Close(); return S_OK; }
                                if (FAILED(status) || !control) { Fail(L"Could not create the application view."); return S_OK; }
                                controller = control;
                                control->get_CoreWebView2(&view);
                                if (!view) { Fail(L"Could not initialize the application view."); return S_OK; }
                                ConfigureView();
                                Resize();
                                return S_OK;
                            }).Get());
                    if (FAILED(create)) Fail(L"Could not create the application view.");
                    return S_OK;
                }).Get());
        if (FAILED(result)) Fail(L"Could not start WebView2. Install Microsoft Edge WebView2 Runtime and reopen Rustorrent.");
    }

    void ConfigureView() {
        ComPtr<ICoreWebView2Settings> settings;
        view->get_Settings(&settings);
        if (settings) {
            settings->put_AreDevToolsEnabled(FALSE);
            settings->put_IsStatusBarEnabled(FALSE);
            settings->put_AreDefaultContextMenusEnabled(FALSE);
            settings->put_IsWebMessageEnabled(FALSE);
            settings->put_AreHostObjectsAllowed(FALSE);
        }
        view->add_NavigationStarting(Callback<ICoreWebView2NavigationStartingEventHandler>(
            [this](ICoreWebView2*, ICoreWebView2NavigationStartingEventArgs* args) -> HRESULT {
                LPWSTR raw = nullptr; args->get_Uri(&raw);
                std::wstring url = raw ? raw : L""; CoTaskMemFree(raw);
                if (!LocalUrl(url, origin)) {
                    args->put_Cancel(TRUE);
                    BOOL user = FALSE; args->get_IsUserInitiated(&user);
                    if (user) OpenExternal(url);
                }
                return S_OK;
            }).Get(), nullptr);
        view->add_NewWindowRequested(Callback<ICoreWebView2NewWindowRequestedEventHandler>(
            [this](ICoreWebView2*, ICoreWebView2NewWindowRequestedEventArgs* args) -> HRESULT {
                args->put_Handled(TRUE);
                LPWSTR raw = nullptr; args->get_Uri(&raw);
                BOOL user = FALSE; args->get_IsUserInitiated(&user);
                if (raw && user) OpenExternal(raw);
                CoTaskMemFree(raw);
                return S_OK;
            }).Get(), nullptr);
        view->add_PermissionRequested(Callback<ICoreWebView2PermissionRequestedEventHandler>(
            [](ICoreWebView2*, ICoreWebView2PermissionRequestedEventArgs* args) -> HRESULT {
                return args->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);
            }).Get(), nullptr);
        view->add_ProcessFailed(Callback<ICoreWebView2ProcessFailedEventHandler>(
            [this](ICoreWebView2*, ICoreWebView2ProcessFailedEventArgs*) -> HRESULT {
                Fail(L"The application view stopped unexpectedly. Reopen Rustorrent to restore your session.");
                return S_OK;
            }).Get(), nullptr);
        view->add_NavigationCompleted(Callback<ICoreWebView2NavigationCompletedEventHandler>(
            [this](ICoreWebView2*, ICoreWebView2NavigationCompletedEventArgs* args) -> HRESULT {
                BOOL success = FALSE; args->get_IsSuccess(&success);
                if (!success) { Fail(L"Could not load the local interface."); return S_OK; }
                loaded = true;
                if (testWindow) std::ofstream(data / L"window-ready.txt") << "ready\n";
                SetWindowTextW(window, L"Rustorrent");
                return S_OK;
            }).Get(), nullptr);
    }

    void SmokeCheck() {
        if (capturePending) return;
        capturePending = true;
        view->ExecuteScript(L"!!document.getElementById('addBtn') && !!document.querySelector('.side')",
            Callback<ICoreWebView2ExecuteScriptCompletedHandler>(
                [this](HRESULT hr, LPCWSTR json) -> HRESULT {
                    if (FAILED(hr) || !json || wcscmp(json, L"true") != 0) {
                        capturePending = false;
                        return S_OK;
                    }
                    std::ofstream(data / L"smoke-success.txt") << "Native window, owned engine and rendered UI are ready.\n";
                    PostMessageW(window, QuitMessage, 0, 0);
                    return S_OK;
                }).Get());
    }

    void Tick() {
        if (closing) {
            if (!backend.value || WaitForSingleObject(backend.value, 0) == WAIT_OBJECT_0) {
                if (backend.value) {
                    DWORD code = 0; GetExitCodeProcess(backend.value, &code);
                    if (code != 0) exitCode = 1;
                }
                DestroyWindow(window);
            } else if (!confirmingForceStop && GetTickCount64() - closingAt > 20000) {
                // The message box runs a modal loop that keeps delivering WM_TIMER here.
                confirmingForceStop = true;
                const bool force = smoke || MessageBoxW(window, L"The engine is still saving its session. Force it to stop?\nUnsaved progress may need to be checked on the next launch.",
                    L"Rustorrent", MB_YESNO | MB_ICONWARNING) == IDYES;
                confirmingForceStop = false;
                // The engine may have finished and closed the window while the box was open.
                if (!IsWindow(window)) return;
                if (force) {
                    TerminateProcess(backend.value, 1);
                    exitCode = 1;
                    DestroyWindow(window);
                } else closingAt = GetTickCount64();
            }
            return;
        }
        // Fail's message box keeps the timer running; do nothing until it closes.
        if (failed) return;
        if (backend.value && WaitForSingleObject(backend.value, 0) == WAIT_OBJECT_0) {
            // Another process may have taken the port before the engine bound it.
            if (ready != 1 && restarts < 2) {
                ++restarts;
                try { LaunchEngine(AvailablePort(false)); }
                catch (const std::exception& error) { Fail(Wide(error.what())); }
                return;
            }
            const std::wstring reason = LastLogLine(data / L"engine.log");
            Fail(reason.empty() ? L"The download engine stopped." : L"The download engine stopped:\n" + reason);
            return;
        }
        if (ready == -1 || ((!loaded || smoke) && GetTickCount64() - started > 45000)) {
            Fail(L"The download engine or application view did not become ready in time."); return;
        }
        if (ready == 1 && view && !navigating) {
            navigating = true;
            view->Navigate((origin + L"/").c_str());
        }
        if (smoke && loaded) SmokeCheck();
    }

    void ShowWindowAgain() {
        ShowWindow(window, SW_RESTORE);
        SetForegroundWindow(window);
        if (controller) controller->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC);
    }

    void Command(UINT command) {
        switch (command) {
        case Add:
            ShowWindowAgain();
            if (loaded) view->ExecuteScript(L"document.getElementById('addBtn').click()", nullptr);
            break;
        case Downloads: ShellExecuteW(window, L"open", downloads.c_str(), nullptr, nullptr, SW_SHOWNORMAL); break;
        case Settings:
            ShowWindowAgain();
            if (loaded) view->ExecuteScript(L"document.querySelector('[data-v=\"settings\"]')?.click()", nullptr);
            break;
        case Reload: if (view && !closing) view->Reload(); break;
        case Hide: if (tray.hWnd) ShowWindow(window, SW_HIDE); break;
        case Show: ShowWindowAgain(); break;
        case Exit: BeginQuit(); break;
        case About: MessageBoxW(window, L"Rustorrent\nA compact BitTorrent client.\n\nWindows desktop host with Microsoft Edge WebView2.\nSee the bundled LICENSE and notices for licensing.", L"About Rustorrent", MB_OK); break;
        }
    }

    void SetupTray() {
        if (smoke) return;
        tray.cbSize = sizeof(tray); tray.hWnd = window; tray.uID = 1;
        tray.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        tray.uCallbackMessage = TrayMessage; tray.hIcon = icon;
        wcscpy_s(tray.szTip, L"Rustorrent");
        if (!Shell_NotifyIconW(NIM_ADD, &tray)) tray.hWnd = nullptr;
    }

    void TrayMenu() {
        HMENU menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, Show, L"Show Rustorrent");
        AppendMenuW(menu, MF_STRING, Add, L"Add torrent…");
        AppendMenuW(menu, MF_STRING, Downloads, L"Open downloads");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, Exit, L"Exit");
        POINT point{}; GetCursorPos(&point); SetForegroundWindow(window);
        UINT chosen = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y, 0, window, nullptr);
        DestroyMenu(menu);
        if (chosen) Command(chosen);
        PostMessageW(window, WM_NULL, 0, 0);
    }
};

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    App* app = reinterpret_cast<App*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        app = static_cast<App*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);
        app->window = window;
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
    }
    if (!app) return DefWindowProcW(window, message, wparam, lparam);
    switch (message) {
    case WM_SIZE: app->Resize(); return 0;
    case WM_DPICHANGED: {
        RECT* bounds = reinterpret_cast<RECT*>(lparam);
        SetWindowPos(window, nullptr, bounds->left, bounds->top, bounds->right - bounds->left,
                     bounds->bottom - bounds->top, SWP_NOZORDER | SWP_NOACTIVATE);
        return 0;
    }
    case WM_GETMINMAXINFO: {
        auto* limits = reinterpret_cast<MINMAXINFO*>(lparam);
        const UINT dpi = GetDpiForWindow(window);
        limits->ptMinTrackSize = {MulDiv(720, dpi, 96), MulDiv(480, dpi, 96)};
        return 0;
    }
    case WM_SETFOCUS: if (app->controller) app->controller->MoveFocus(COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC); return 0;
    case WM_COMMAND: app->Command(LOWORD(wparam)); return 0;
    case WM_TIMER: app->Tick(); return 0;
    case WM_CLOSE: case QuitMessage: app->BeginQuit(); return 0;
    case WM_QUERYENDSESSION: if (app->shutdown.value) SetEvent(app->shutdown.value); return TRUE;
    case WM_ENDSESSION: if (wparam) app->BeginQuit(); return 0;
    case TrayMessage:
        if (lparam == WM_LBUTTONDBLCLK) app->ShowWindowAgain();
        else if (lparam == WM_RBUTTONUP) app->TrayMenu();
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT paint{}; HDC dc = BeginPaint(window, &paint);
        RECT bounds{}; GetClientRect(window, &bounds);
        SetBkMode(dc, TRANSPARENT);
        SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
        DrawTextW(dc, app->closing ? L"Saving your session…" : L"Starting Rustorrent…", -1, &bounds,
                  DT_SINGLELINE | DT_CENTER | DT_VCENTER);
        EndPaint(window, &paint); return 0;
    }
    case WM_DESTROY: KillTimer(window, 1); PostQuitMessage(app->exitCode); return 0;
    }
    static const UINT taskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");
    if (message == taskbarCreated) { app->SetupTray(); return 0; }
    return DefWindowProcW(window, message, wparam, lparam);
}

int SelfTest() {
    for (const auto& value : {std::wstring(L""), std::wstring(L"C:\\a path\\"),
                              std::wstring(L"quote\"slash\\\""), std::wstring(L"Загрузки\\файл")}) {
        int count = 0;
        LPWSTR* args = CommandLineToArgvW((L"test " + Quote(value)).c_str(), &count);
        bool valid = args && count == 2 && args[1] == value;
        LocalFree(args);
        if (!valid) return 1;
    }
    const std::wstring origin = L"http://127.0.0.1:9473";
    if (!LocalUrl(origin + L"/", origin) || !LocalUrl(origin + L"/app.js", origin) ||
        LocalUrl(origin + L"0/", origin) || LocalUrl(origin + L"@evil.test/", origin) ||
        LocalUrl(L"file:///C:/Windows", origin) || ExternalUrl(L"javascript:alert(1)")) return 2;
    return 0;
}
} // namespace

int WINAPI wWinMain(HINSTANCE module, HINSTANCE, PWSTR, int) {
    int count = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &count);
    if (!arguments) return 1;
    if (count == 2 && wcscmp(arguments[1], L"--self-test") == 0) { LocalFree(arguments); return SelfTest(); }
    HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(com)) { LocalFree(arguments); return 1; }
    WSADATA sockets{};
    if (WSAStartup(MAKEWORD(2, 2), &sockets) != 0) { LocalFree(arguments); CoUninitialize(); return 1; }
    int exitCode = 1;
    {
        App app;
        try {
            app.smoke = count == 3 && wcscmp(arguments[1], L"--smoke-test") == 0;
            app.testWindow = count == 3 && wcscmp(arguments[1], L"--test-window") == 0;
            app.data = (app.smoke || app.testWindow) ? fs::absolute(arguments[2]) : KnownFolder(FOLDERID_LocalAppData) / L"Rustorrent";
            app.downloads = (app.smoke || app.testWindow) ? app.data / L"Downloads" : KnownFolder(FOLDERID_Downloads);
            if (!app.smoke && !app.testWindow && count != 1) throw std::runtime_error("Start Rustorrent.exe without command-line arguments. Use rustorrent-bin.exe for CLI options.");
            fs::create_directories(app.data);
            fs::create_directories(app.downloads);
            if (!app.smoke && !app.testWindow) {
                app.instance.value = CreateMutexW(nullptr, TRUE, L"Local\\Rustorrent.Desktop.Instance");
                if (!app.instance.value) throw std::runtime_error("Could not create the application lock.");
                if (GetLastError() == ERROR_ALREADY_EXISTS) {
                    HWND previous = FindWindowW(WindowClass, nullptr);
                    if (previous) { ShowWindow(previous, SW_RESTORE); SetForegroundWindow(previous); }
                    else MessageBoxW(nullptr, L"Rustorrent is already starting. Please wait for its window.", L"Rustorrent", MB_OK);
                    LocalFree(arguments); WSACleanup(); CoUninitialize(); return 0;
                }
            }
            wchar_t path[32768];
            DWORD pathLength = GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
            if (!pathLength || pathLength >= ARRAYSIZE(path)) throw std::runtime_error("Could not locate Rustorrent.exe.");
            app.executable = path;
            app.icon = LoadIconW(module, MAKEINTRESOURCEW(1));
            WNDCLASSEXW windowClass{}; windowClass.cbSize = sizeof(windowClass);
            windowClass.hInstance = module; windowClass.lpfnWndProc = WindowProc;
            windowClass.lpszClassName = WindowClass; windowClass.hIcon = app.icon; windowClass.hIconSm = app.icon;
            windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW); windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
            if (!RegisterClassExW(&windowClass)) throw std::runtime_error("Could not register the application window.");
            HMENU menu = CreateMenu(), file = CreatePopupMenu(), help = CreatePopupMenu();
            AppendMenuW(file, MF_STRING, Add, L"&Add torrent…\tCtrl+O");
            AppendMenuW(file, MF_STRING, Downloads, L"Open &downloads");
            AppendMenuW(file, MF_STRING, Settings, L"&Settings");
            AppendMenuW(file, MF_STRING, Reload, L"&Reload");
            AppendMenuW(file, MF_SEPARATOR, 0, nullptr);
            AppendMenuW(file, MF_STRING, Hide, L"Hide to &tray");
            AppendMenuW(file, MF_STRING, Exit, L"E&xit");
            AppendMenuW(help, MF_STRING, About, L"&About Rustorrent");
            AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(file), L"&File");
            AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(help), L"&Help");
            HWND window = CreateWindowExW(0, WindowClass, L"Rustorrent — Starting…", WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT, CW_USEDEFAULT, 1180, 780, nullptr, menu, module, &app);
            if (!window) throw std::runtime_error("Could not create the application window.");
            SetTimer(window, 1, 150, nullptr);
            if (!app.smoke) ShowWindow(window, SW_SHOW);
            app.SetupTray();
            app.StartBackend();
            app.CreateView();
            MSG message{};
            while (GetMessageW(&message, nullptr, 0, 0) > 0) {
                TranslateMessage(&message); DispatchMessageW(&message);
            }
            exitCode = app.exitCode;
        } catch (const std::exception& error) {
            if (!app.data.empty()) std::ofstream(app.data / L"launcher-error.txt") << error.what();
            if (!app.smoke) MessageBoxW(app.window, Wide(error.what()).c_str(), L"Rustorrent", MB_OK | MB_ICONERROR);
            if (app.window && IsWindow(app.window)) DestroyWindow(app.window);
        }
    }
    LocalFree(arguments);
    WSACleanup();
    CoUninitialize();
    return exitCode;
}
