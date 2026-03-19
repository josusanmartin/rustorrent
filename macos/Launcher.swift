import AppKit
import Foundation
import UniformTypeIdentifiers
import WebKit

@main
final class RustorrentLauncher: NSObject, NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate, NSToolbarDelegate {
    private let uiPort = 9473
    private let maxUiWaitAttempts = 150
    private let openUiOnLaunchKey = "open_ui_on_launch"
    private let downloadDirectoryKey = "download_directory"

    private let toolbarIdentifier = NSToolbar.Identifier("RustorrentToolbar")
    private let toolbarAddItemIdentifier = NSToolbarItem.Identifier("RustorrentToolbarAdd")
    private let toolbarRefreshItemIdentifier = NSToolbarItem.Identifier("RustorrentToolbarRefresh")
    private let toolbarDownloadsItemIdentifier = NSToolbarItem.Identifier("RustorrentToolbarDownloads")
    private let toolbarPreferencesItemIdentifier = NSToolbarItem.Identifier("RustorrentToolbarPreferences")

    private var backendProcess: Process?
    private var backendOwned = false
    private var uiReadyTimer: Timer?
    private var uiWaitAttempts = 0
    private var pendingTorrentFiles: [URL] = []
    private var logHandle: FileHandle?
    private var openUiWhenReady = true
    private var cachedApiToken: String?

    private var preferencesWindow: NSWindow?
    private var openUiCheckbox: NSButton?
    private var downloadDirField: NSTextField?
    private var mainWindow: NSWindow?
    private var webView: WKWebView?
    private var lastLoadedURL: URL?
    private var statusItem: NSStatusItem?
    private lazy var dockMenu: NSMenu = makeQuickMenu()

    static func main() {
        let app = NSApplication.shared
        let delegate = RustorrentLauncher()
        app.delegate = delegate
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        prepareLauncherLogIfNeeded()
        log("application did finish launching")
        buildMenus()
        buildStatusItem()
        collectStartupTorrentFiles(from: CommandLine.arguments)
        openUiWhenReady = openUiOnLaunchEnabled() || !pendingTorrentFiles.isEmpty
        if openUiWhenReady {
            showMainWindow()
            loadPlaceholderPage(
                title: "Starting Rustorrent",
                message: "Launching the local engine and loading the built-in interface."
            )
        }

        scheduleUiBootstrap(timeout: 0.8)

        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationDockMenu(_ sender: NSApplication) -> NSMenu? {
        dockMenu
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openUiWhenReady = true
        showMainWindow()
        openWebUi()
        return true
    }

    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        enqueueTorrentFiles(from: filenames)
        openUiWhenReady = true
        showMainWindow()
        loadPlaceholderPage(
            title: "Adding Torrent",
            message: "Waiting for the local interface so the torrent can be handed off."
        )
        scheduleUiBootstrap(timeout: 0.6)
        sender.reply(toOpenOrPrint: .success)
    }

    func applicationWillTerminate(_ notification: Notification) {
        log("application will terminate")
        uiReadyTimer?.invalidate()
        uiReadyTimer = nil

        if backendOwned {
            backendProcess?.terminate()
        }
        backendProcess = nil

        try? logHandle?.close()
        logHandle = nil
    }

    @objc
    private func showAboutPanel() {
        NSApp.orderFrontStandardAboutPanel(nil)
    }

    @objc
    private func showPreferencesWindow() {
        if let window = preferencesWindow {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 220),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "Rustorrent Preferences"
        window.isReleasedWhenClosed = false

        let content = NSView(frame: window.contentRect(forFrameRect: window.frame))
        window.contentView = content

        let openUi = NSButton(
            checkboxWithTitle: "Open Rustorrent window when launching",
            target: self,
            action: #selector(toggleOpenUiOnLaunch(_:))
        )
        openUi.frame = NSRect(x: 20, y: 170, width: 500, height: 24)
        content.addSubview(openUi)

        let dirLabel = NSTextField(labelWithString: "Download Directory")
        dirLabel.frame = NSRect(x: 20, y: 130, width: 200, height: 18)
        content.addSubview(dirLabel)

        let dirField = NSTextField(frame: NSRect(x: 20, y: 94, width: 420, height: 30))
        dirField.isEditable = false
        dirField.isSelectable = true
        dirField.usesSingleLineMode = true
        dirField.lineBreakMode = .byTruncatingMiddle
        content.addSubview(dirField)

        let chooseDir = NSButton(title: "Choose…", target: self, action: #selector(chooseDownloadDirectory))
        chooseDir.frame = NSRect(x: 450, y: 94, width: 90, height: 30)
        content.addSubview(chooseDir)

        let launchNow = NSButton(title: "Open Window", target: self, action: #selector(openWebUiFromMenu))
        launchNow.frame = NSRect(x: 20, y: 48, width: 120, height: 30)
        content.addSubview(launchNow)

        let note = NSTextField(
            labelWithString: "Download directory changes apply to newly launched backend sessions."
        )
        note.frame = NSRect(x: 20, y: 20, width: 520, height: 18)
        note.textColor = NSColor.secondaryLabelColor
        note.font = NSFont.systemFont(ofSize: 11)
        content.addSubview(note)

        preferencesWindow = window
        openUiCheckbox = openUi
        downloadDirField = dirField
        refreshPreferencesControls()

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    @objc
    private func openWebUiFromMenu() {
        openUiWhenReady = true
        showMainWindow()
        loadPlaceholderPage(
            title: "Opening Rustorrent",
            message: "Preparing the built-in interface."
        )
        scheduleUiBootstrap(timeout: 0.6)
    }

    @objc
    private func reloadCurrentWindow() {
        if isUiReachable(timeout: 0.3) {
            showMainWindow()
            if let webView, webView.url != nil {
                webView.reload()
            } else {
                openWebUi()
            }
        } else {
            openWebUiFromMenu()
        }
    }

    @objc
    private func openDownloadsFromMenu() {
        NSWorkspace.shared.open(currentDownloadDirectoryURL())
    }

    @objc
    private func addTorrentFileFromMenu() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = true
        if #available(macOS 12.0, *) {
            panel.allowedContentTypes = [UTType(filenameExtension: "torrent") ?? .data]
        } else {
            panel.allowedFileTypes = ["torrent"]
        }
        panel.title = "Add Torrent File"

        panel.begin { [weak self] response in
            guard let self else { return }
            guard response == .OK else { return }
            self.pendingTorrentFiles.append(contentsOf: panel.urls)
            self.openUiWhenReady = true
            self.showMainWindow()
            self.loadPlaceholderPage(
                title: "Adding Torrent",
                message: "Preparing the local interface and queueing the selected files."
            )
            self.scheduleUiBootstrap(timeout: 0.6)
        }
    }

    @objc
    private func quitFromMenu() {
        NSApp.terminate(nil)
    }

    @objc
    private func openHelpFromMenu() {
        openWebUiFromMenu()
    }

    @objc
    private func toggleOpenUiOnLaunch(_ sender: NSButton) {
        setOpenUiOnLaunchEnabled(sender.state == .on)
    }

    @objc
    private func chooseDownloadDirectory() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Use Folder"
        panel.directoryURL = currentDownloadDirectoryURL()

        panel.begin { [weak self] response in
            guard let self else { return }
            guard response == .OK, let url = panel.url else { return }
            self.setCurrentDownloadDirectoryURL(url)
            self.refreshPreferencesControls()
        }
    }

    private func buildMenus() {
        let mainMenu = NSMenu()
        NSApp.mainMenu = mainMenu

        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)
        let appMenu = NSMenu()
        appMenuItem.submenu = appMenu

        let about = NSMenuItem(title: "About Rustorrent", action: #selector(showAboutPanel), keyEquivalent: "")
        about.target = self
        appMenu.addItem(about)

        appMenu.addItem(NSMenuItem.separator())

        let preferences = NSMenuItem(
            title: "Preferences…",
            action: #selector(showPreferencesWindow),
            keyEquivalent: ","
        )
        preferences.target = self
        appMenu.addItem(preferences)

        appMenu.addItem(NSMenuItem.separator())

        let launchUi = NSMenuItem(title: "Show Window", action: #selector(openWebUiFromMenu), keyEquivalent: "l")
        launchUi.target = self
        launchUi.keyEquivalentModifierMask = [.command]
        appMenu.addItem(launchUi)

        let openDownloads = NSMenuItem(
            title: "Open Downloads",
            action: #selector(openDownloadsFromMenu),
            keyEquivalent: "o"
        )
        openDownloads.target = self
        openDownloads.keyEquivalentModifierMask = [.command, .shift]
        appMenu.addItem(openDownloads)

        let addTorrent = NSMenuItem(
            title: "Add Torrent File…",
            action: #selector(addTorrentFileFromMenu),
            keyEquivalent: "t"
        )
        addTorrent.target = self
        addTorrent.keyEquivalentModifierMask = [.command]
        appMenu.addItem(addTorrent)

        appMenu.addItem(NSMenuItem.separator())

        let hide = NSMenuItem(
            title: "Hide Rustorrent",
            action: #selector(NSApplication.hide(_:)),
            keyEquivalent: "h"
        )
        hide.target = NSApp
        appMenu.addItem(hide)

        let hideOthers = NSMenuItem(
            title: "Hide Others",
            action: #selector(NSApplication.hideOtherApplications(_:)),
            keyEquivalent: "h"
        )
        hideOthers.target = NSApp
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(hideOthers)

        let showAll = NSMenuItem(
            title: "Show All",
            action: #selector(NSApplication.unhideAllApplications(_:)),
            keyEquivalent: ""
        )
        showAll.target = NSApp
        appMenu.addItem(showAll)

        appMenu.addItem(NSMenuItem.separator())

        let quit = NSMenuItem(title: "Quit Rustorrent", action: #selector(quitFromMenu), keyEquivalent: "q")
        quit.target = self
        quit.keyEquivalentModifierMask = [.command]
        appMenu.addItem(quit)

        let fileMenuItem = NSMenuItem()
        mainMenu.addItem(fileMenuItem)
        let fileMenu = NSMenu(title: "File")
        fileMenuItem.submenu = fileMenu

        let fileAdd = NSMenuItem(
            title: "Add Torrent File…",
            action: #selector(addTorrentFileFromMenu),
            keyEquivalent: "t"
        )
        fileAdd.target = self
        fileAdd.keyEquivalentModifierMask = [.command]
        fileMenu.addItem(fileAdd)

        fileMenu.addItem(NSMenuItem.separator())

        let fileLaunch = NSMenuItem(title: "Show Window", action: #selector(openWebUiFromMenu), keyEquivalent: "l")
        fileLaunch.target = self
        fileLaunch.keyEquivalentModifierMask = [.command]
        fileMenu.addItem(fileLaunch)

        let windowMenuItem = NSMenuItem()
        mainMenu.addItem(windowMenuItem)
        let windowMenu = NSMenu(title: "Window")
        windowMenuItem.submenu = windowMenu
        NSApp.windowsMenu = windowMenu

        let minimize = NSMenuItem(
            title: "Minimize",
            action: #selector(NSWindow.performMiniaturize(_:)),
            keyEquivalent: "m"
        )
        windowMenu.addItem(minimize)

        let zoom = NSMenuItem(title: "Zoom", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        windowMenu.addItem(zoom)

        windowMenu.addItem(NSMenuItem.separator())
        windowMenu.addItem(
            NSMenuItem(title: "Bring All to Front", action: #selector(NSApplication.arrangeInFront(_:)), keyEquivalent: "")
        )

        let helpMenuItem = NSMenuItem()
        mainMenu.addItem(helpMenuItem)
        let helpMenu = NSMenu(title: "Help")
        helpMenuItem.submenu = helpMenu
        NSApp.helpMenu = helpMenu

        let help = NSMenuItem(title: "Rustorrent Help", action: #selector(openHelpFromMenu), keyEquivalent: "?")
        help.target = self
        helpMenu.addItem(help)
    }

    private func scheduleUiBootstrap(timeout: TimeInterval) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let reachable = self.isUiReachable(timeout: timeout)
            DispatchQueue.main.async {
                if reachable {
                    self.flushPendingTorrents()
                    if self.openUiWhenReady {
                        self.openWebUi()
                    }
                } else {
                    self.startBackendIfNeeded()
                    self.waitForUiReady()
                }
            }
        }
    }

    private func buildStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = item.button {
            button.image = NSImage(
                systemSymbolName: "arrow.down.circle",
                accessibilityDescription: "Rustorrent"
            )
            button.image?.isTemplate = true
            button.toolTip = "Rustorrent"
        }
        item.menu = makeQuickMenu()
        statusItem = item
    }

    private func makeQuickMenu() -> NSMenu {
        let menu = NSMenu()

        let showWindow = NSMenuItem(title: "Show Window", action: #selector(openWebUiFromMenu), keyEquivalent: "")
        showWindow.target = self
        menu.addItem(showWindow)

        let addTorrent = NSMenuItem(title: "Add Torrent File…", action: #selector(addTorrentFileFromMenu), keyEquivalent: "")
        addTorrent.target = self
        menu.addItem(addTorrent)

        let openDownloads = NSMenuItem(title: "Open Downloads", action: #selector(openDownloadsFromMenu), keyEquivalent: "")
        openDownloads.target = self
        menu.addItem(openDownloads)

        menu.addItem(NSMenuItem.separator())

        let preferences = NSMenuItem(title: "Preferences…", action: #selector(showPreferencesWindow), keyEquivalent: "")
        preferences.target = self
        menu.addItem(preferences)

        let refresh = NSMenuItem(title: "Reload", action: #selector(reloadCurrentWindow), keyEquivalent: "")
        refresh.target = self
        menu.addItem(refresh)

        menu.addItem(NSMenuItem.separator())

        let quit = NSMenuItem(title: "Quit Rustorrent", action: #selector(quitFromMenu), keyEquivalent: "")
        quit.target = self
        menu.addItem(quit)
        return menu
    }

    private func createMainWindowIfNeeded() {
        guard mainWindow == nil else { return }
        log("creating main window")

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1240, height: 860),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "Rustorrent"
        window.minSize = NSSize(width: 960, height: 640)
        window.isReleasedWhenClosed = false
        window.delegate = self
        if #available(macOS 11.0, *) {
            window.toolbarStyle = .unifiedCompact
        }
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        let toolbar = NSToolbar(identifier: toolbarIdentifier)
        toolbar.delegate = self
        toolbar.displayMode = .iconOnly
        toolbar.allowsUserCustomization = false
        toolbar.autosavesConfiguration = false
        window.toolbar = toolbar

        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        let webView = WKWebView(frame: window.contentView?.bounds ?? .zero, configuration: configuration)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.allowsBackForwardNavigationGestures = true
        webView.autoresizingMask = [.width, .height]
        webView.setValue(false, forKey: "drawsBackground")
        window.contentView = webView

        mainWindow = window
        self.webView = webView
    }

    private func showMainWindow() {
        createMainWindowIfNeeded()
        log("showing main window")
        mainWindow?.orderFrontRegardless()
        mainWindow?.makeKey()
        mainWindow?.makeMain()
        mainWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func loadPlaceholderPage(title: String, message: String, isError: Bool = false) {
        createMainWindowIfNeeded()
        let accent = isError ? "#b3261e" : "#0b57d0"
        let background = isError ? "#fff8f6" : "#f6f8fb"
        let border = isError ? "#f2b8b5" : "#d3e3fd"
        let html = """
        <!doctype html>
        <html>
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <style>
        :root { color-scheme: light; }
        body {
          margin: 0;
          font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
          background: #eef2f7;
          color: #1f2937;
          display: grid;
          place-items: center;
          min-height: 100vh;
        }
        .card {
          width: min(520px, calc(100vw - 48px));
          border-radius: 24px;
          border: 1px solid \(border);
          background: \(background);
          box-shadow: 0 20px 50px rgba(15, 23, 42, 0.12);
          padding: 28px 28px 24px;
        }
        .title {
          margin: 0;
          font-size: 24px;
          font-weight: 700;
          letter-spacing: -0.02em;
          color: \(accent);
        }
        .copy {
          margin-top: 10px;
          font-size: 15px;
          line-height: 1.6;
          color: #475467;
        }
        .pulse {
          width: 12px;
          height: 12px;
          border-radius: 999px;
          background: \(accent);
          box-shadow: 0 0 0 rgba(11, 87, 208, 0.4);
          animation: pulse 1.6s infinite;
          margin-bottom: 16px;
        }
        @keyframes pulse {
          0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(11, 87, 208, 0.35); }
          70% { transform: scale(1); box-shadow: 0 0 0 16px rgba(11, 87, 208, 0); }
          100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(11, 87, 208, 0); }
        }
        </style>
        </head>
        <body>
          <div class="card">
            <div class="pulse"></div>
            <h1 class="title">\(escapeHTML(title))</h1>
            <div class="copy">\(escapeHTML(message))</div>
          </div>
        </body>
        </html>
        """
        webView?.loadHTMLString(html, baseURL: nil)
    }

    private func refreshPreferencesControls() {
        openUiCheckbox?.state = openUiOnLaunchEnabled() ? .on : .off
        downloadDirField?.stringValue = currentDownloadDirectoryURL().path
    }

    private func collectStartupTorrentFiles(from args: [String]) {
        let filteredArgs = args.dropFirst().filter { !$0.hasPrefix("-psn_") }
        enqueueTorrentFiles(from: filteredArgs)
    }

    private func enqueueTorrentFiles(from paths: [String]) {
        for path in paths {
            guard path.lowercased().hasSuffix(".torrent") else { continue }
            let url = URL(fileURLWithPath: path)
            guard FileManager.default.fileExists(atPath: url.path) else { continue }
            pendingTorrentFiles.append(url)
        }
    }

    private func startBackendIfNeeded() {
        if backendProcess != nil {
            return
        }

        let binary = backendBinaryURL()
        guard FileManager.default.isExecutableFile(atPath: binary.path) else {
            presentFatalError(
                title: "Rustorrent Binary Missing",
                text: "Could not find rustorrent-bin inside the app bundle."
            )
            return
        }

        let downloadDir = currentDownloadDirectoryURL()
        let logFile = launcherLogFileURL()
        let homeDir = FileManager.default.homeDirectoryForCurrentUser

        do {
            try FileManager.default.createDirectory(
                at: downloadDir,
                withIntermediateDirectories: true
            )
            try FileManager.default.createDirectory(
                at: logFile.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            if !FileManager.default.fileExists(atPath: logFile.path) {
                FileManager.default.createFile(atPath: logFile.path, contents: nil)
            }
            prepareLauncherLogIfNeeded()
        } catch {
            presentFatalError(
                title: "Rustorrent Startup Failed",
                text: "Could not prepare app directories: \(error.localizedDescription)"
            )
            return
        }

        let process = Process()
        process.executableURL = binary
        process.arguments = [
            "--ui",
            "--ui-addr",
            "127.0.0.1:\(uiPort)",
            "--download-dir",
            downloadDir.path,
            "--log",
            logFile.path,
        ]
        process.currentDirectoryURL = homeDir
        if let logHandle {
            process.standardOutput = logHandle
            process.standardError = logHandle
        }

        process.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async {
                self?.handleBackendExit(proc)
            }
        }

        do {
            try process.run()
            backendProcess = process
            backendOwned = true
            log("started backend pid \(process.processIdentifier)")
        } catch {
            presentFatalError(
                title: "Rustorrent Startup Failed",
                text: "Could not launch rustorrent-bin: \(error.localizedDescription)"
            )
        }
    }

    private func handleBackendExit(_ proc: Process) {
        log("backend exited status \(proc.terminationStatus)")
        backendProcess = nil
        backendOwned = false
        cachedApiToken = nil
        if !isUiReachable(timeout: 0.4) {
            loadPlaceholderPage(
                title: "Rustorrent Stopped",
                message: "The local engine exited with status \(proc.terminationStatus). Relaunch the window to try again.",
                isError: true
            )
            presentFatalError(
                title: "Rustorrent Stopped",
                text: "The background process exited with status \(proc.terminationStatus)."
            )
        }
    }

    private func waitForUiReady() {
        if uiReadyTimer != nil {
            return
        }
        uiWaitAttempts = 0
        uiReadyTimer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] timer in
            guard let self else {
                timer.invalidate()
                return
            }
            self.uiWaitAttempts += 1
            if self.isUiReachable(timeout: 0.6) {
                self.log("ui reachable after \(self.uiWaitAttempts) attempts")
                timer.invalidate()
                self.uiReadyTimer = nil
                self.flushPendingTorrents()
                if self.openUiWhenReady {
                    self.showMainWindow()
                    self.openWebUi()
                }
                return
            }
            if self.uiWaitAttempts >= self.maxUiWaitAttempts {
                self.log("ui failed to become ready within timeout")
                timer.invalidate()
                self.uiReadyTimer = nil
                self.loadPlaceholderPage(
                    title: "Rustorrent UI Timeout",
                    message: "The local interface did not become ready in time. Try relaunching the window.",
                    isError: true
                )
                self.presentFatalError(
                    title: "Rustorrent UI Timeout",
                    text: "The local web UI did not become ready in time."
                )
            }
        }
        if let uiReadyTimer {
            RunLoop.main.add(uiReadyTimer, forMode: .common)
        }
    }

    private func flushPendingTorrents() {
        if pendingTorrentFiles.isEmpty {
            return
        }
        log("flushing \(pendingTorrentFiles.count) pending torrents")
        var remaining: [URL] = []
        for file in pendingTorrentFiles {
            if !postTorrentFile(file) {
                remaining.append(file)
            }
        }
        pendingTorrentFiles = remaining
    }

    private func postTorrentFile(_ file: URL) -> Bool {
        guard let token = fetchApiToken() else {
            log("failed to fetch api token; cannot add torrent \(file.lastPathComponent)")
            return false
        }

        let base = uiBaseURL().appendingPathComponent("add-torrent")
        var components = URLComponents(url: base, resolvingAgainstBaseURL: false)
        components?.queryItems = [
            URLQueryItem(name: "dir", value: currentDownloadDirectoryURL().path),
            URLQueryItem(name: "prealloc", value: "0"),
        ]
        let endpoint = components?.string ?? base.absoluteString
        let origin = "http://127.0.0.1:\(uiPort)"

        let firstTry = runCurl([
            "-sS",
            "--connect-timeout", "1",
            "--max-time", "6",
            "-X", "POST",
            "-H", "Origin: \(origin)",
            "-H", "X-Rustorrent-Token: \(token)",
            "-H", "Content-Type: application/x-bittorrent",
            "--data-binary", "@\(file.path)",
            endpoint,
        ])
        if firstTry.status == 0 {
            return true
        }

        // Token may have rotated; refresh once and retry.
        cachedApiToken = nil
        guard let retryToken = fetchApiToken() else {
            log("failed to refresh api token while adding \(file.lastPathComponent)")
            return false
        }
        let retry = runCurl([
            "-sS",
            "--connect-timeout", "1",
            "--max-time", "6",
            "-X", "POST",
            "-H", "Origin: \(origin)",
            "-H", "X-Rustorrent-Token: \(retryToken)",
            "-H", "Content-Type: application/x-bittorrent",
            "--data-binary", "@\(file.path)",
            endpoint,
        ])
        if retry.status != 0 {
            log("failed to post torrent \(file.lastPathComponent)")
        }
        return retry.status == 0
    }

    private func openWebUi() {
        let url = uiBaseURL()
        showMainWindow()
        log("opening ui url \(url.absoluteString)")
        if lastLoadedURL != url {
            webView?.load(URLRequest(url: url))
            lastLoadedURL = url
        } else {
            webView?.reload()
        }
    }

    private func isUiReachable(timeout: TimeInterval) -> Bool {
        let timeoutSecs = String(max(1, Int(ceil(timeout))))
        let result = runCurl([
            "-sS",
            "--connect-timeout", timeoutSecs,
            "--max-time", timeoutSecs,
            uiBaseURL().appendingPathComponent("api-token").absoluteString,
        ])
        if result.status == 0 {
            if let token = parseApiToken(from: result.output) {
                cachedApiToken = token
            }
            return true
        }
        return false
    }

    private func fetchApiToken() -> String? {
        if let token = cachedApiToken, !token.isEmpty {
            return token
        }
        let result = runCurl([
            "-sS",
            "--connect-timeout", "1",
            "--max-time", "3",
            uiBaseURL().appendingPathComponent("api-token").absoluteString,
        ])
        guard result.status == 0 else {
            return nil
        }
        cachedApiToken = parseApiToken(from: result.output)
        return cachedApiToken
    }

    private func parseApiToken(from raw: String) -> String? {
        guard let data = raw.data(using: .utf8) else {
            return nil
        }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        guard let token = object["token"] as? String, !token.isEmpty else {
            return nil
        }
        return token
    }

    private func runCurl(_ arguments: [String]) -> (status: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
        process.arguments = arguments
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        do {
            try process.run()
        } catch {
            return (-1, "")
        }
        process.waitUntilExit()
        let out = outPipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: out, encoding: .utf8) ?? ""
        return (process.terminationStatus, output)
    }

    private func presentFatalError(title: String, text: String) {
        log("fatal: \(title): \(text)")
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = title
        alert.informativeText = text
        alert.addButton(withTitle: "Quit")
        alert.runModal()
        NSApp.terminate(nil)
    }

    private func log(_ message: String) {
        guard let logHandle else { return }
        let line = "[\(isoTimestamp())] \(message)\n"
        if let data = line.data(using: .utf8) {
            logHandle.write(data)
        }
    }

    private func prepareLauncherLogIfNeeded() {
        if logHandle != nil {
            return
        }
        let logFile = launcherLogFileURL()
        do {
            try FileManager.default.createDirectory(
                at: logFile.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            if !FileManager.default.fileExists(atPath: logFile.path) {
                FileManager.default.createFile(atPath: logFile.path, contents: nil)
            }
            logHandle = try FileHandle(forWritingTo: logFile)
            logHandle?.seekToEndOfFile()
        } catch {
            // Fall back to no-op logging if file setup fails.
        }
    }

    private func isoTimestamp() -> String {
        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime]
        return fmt.string(from: Date())
    }

    private func uiBaseURL() -> URL {
        URL(string: "http://127.0.0.1:\(uiPort)")!
    }

    private func backendBinaryURL() -> URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/rustorrent-bin")
    }

    private func openUiOnLaunchEnabled() -> Bool {
        let defaults = UserDefaults.standard
        if defaults.object(forKey: openUiOnLaunchKey) == nil {
            return true
        }
        return defaults.bool(forKey: openUiOnLaunchKey)
    }

    private func setOpenUiOnLaunchEnabled(_ enabled: Bool) {
        UserDefaults.standard.set(enabled, forKey: openUiOnLaunchKey)
    }

    private func currentDownloadDirectoryURL() -> URL {
        if let path = UserDefaults.standard.string(forKey: downloadDirectoryKey), !path.isEmpty {
            return URL(fileURLWithPath: path, isDirectory: true)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Downloads", isDirectory: true)
    }

    private func setCurrentDownloadDirectoryURL(_ url: URL) {
        UserDefaults.standard.set(url.path, forKey: downloadDirectoryKey)
    }

    private func launcherLogFileURL() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".rustorrent", isDirectory: true)
            .appendingPathComponent("launcher.log")
    }

    private func escapeHTML(_ text: String) -> String {
        text
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [
            toolbarAddItemIdentifier,
            toolbarRefreshItemIdentifier,
            toolbarDownloadsItemIdentifier,
            toolbarPreferencesItemIdentifier,
            .flexibleSpace,
            .space,
        ]
    }

    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [
            toolbarAddItemIdentifier,
            .flexibleSpace,
            toolbarRefreshItemIdentifier,
            toolbarDownloadsItemIdentifier,
            toolbarPreferencesItemIdentifier,
        ]
    }

    func toolbar(
        _ toolbar: NSToolbar,
        itemForItemIdentifier itemIdentifier: NSToolbarItem.Identifier,
        willBeInsertedIntoToolbar flag: Bool
    ) -> NSToolbarItem? {
        let item = NSToolbarItem(itemIdentifier: itemIdentifier)
        item.target = self

        switch itemIdentifier {
        case toolbarAddItemIdentifier:
            item.label = "Add Torrent"
            item.paletteLabel = item.label
            item.toolTip = "Add a .torrent file"
            item.image = NSImage(systemSymbolName: "plus.circle", accessibilityDescription: item.label)
            item.action = #selector(addTorrentFileFromMenu)
        case toolbarRefreshItemIdentifier:
            item.label = "Reload"
            item.paletteLabel = item.label
            item.toolTip = "Reload the Rustorrent window"
            item.image = NSImage(systemSymbolName: "arrow.clockwise", accessibilityDescription: item.label)
            item.action = #selector(reloadCurrentWindow)
        case toolbarDownloadsItemIdentifier:
            item.label = "Downloads"
            item.paletteLabel = item.label
            item.toolTip = "Open the download directory"
            item.image = NSImage(systemSymbolName: "folder", accessibilityDescription: item.label)
            item.action = #selector(openDownloadsFromMenu)
        case toolbarPreferencesItemIdentifier:
            item.label = "Preferences"
            item.paletteLabel = item.label
            item.toolTip = "Open Rustorrent preferences"
            item.image = NSImage(systemSymbolName: "gearshape", accessibilityDescription: item.label)
            item.action = #selector(showPreferencesWindow)
        default:
            return nil
        }
        return item
    }

    func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        guard let url = navigationAction.request.url else {
            decisionHandler(.allow)
            return
        }

        let isLocalUI = (url.scheme == "http" || url.scheme == "https")
            && url.host == "127.0.0.1"
            && (url.port ?? uiPort) == uiPort
        if isLocalUI || url.scheme == "about" {
            decisionHandler(.allow)
            return
        }

        NSWorkspace.shared.open(url)
        decisionHandler(.cancel)
    }

    func webView(
        _ webView: WKWebView,
        createWebViewWith configuration: WKWebViewConfiguration,
        for navigationAction: WKNavigationAction,
        windowFeatures: WKWindowFeatures
    ) -> WKWebView? {
        if let url = navigationAction.request.url {
            NSWorkspace.shared.open(url)
        }
        return nil
    }

    func webView(
        _ webView: WKWebView,
        runJavaScriptAlertPanelWithMessage message: String,
        initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping () -> Void
    ) {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "Rustorrent"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        if let window = webView.window ?? mainWindow ?? NSApp.keyWindow {
            alert.beginSheetModal(for: window) { _ in
                completionHandler()
            }
        } else {
            let _ = alert.runModal()
            completionHandler()
        }
    }

    func webView(
        _ webView: WKWebView,
        runJavaScriptConfirmPanelWithMessage message: String,
        initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping (Bool) -> Void
    ) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Rustorrent"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        if let window = webView.window ?? mainWindow ?? NSApp.keyWindow {
            alert.beginSheetModal(for: window) { response in
                completionHandler(response == .alertFirstButtonReturn)
            }
        } else {
            let response = alert.runModal()
            completionHandler(response == .alertFirstButtonReturn)
        }
    }

    func webView(
        _ webView: WKWebView,
        runJavaScriptTextInputPanelWithPrompt prompt: String,
        defaultText: String?,
        initiatedByFrame frame: WKFrameInfo,
        completionHandler: @escaping (String?) -> Void
    ) {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "Rustorrent"
        alert.informativeText = prompt
        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        input.stringValue = defaultText ?? ""
        alert.accessoryView = input
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        if let window = webView.window ?? mainWindow ?? NSApp.keyWindow {
            alert.beginSheetModal(for: window) { response in
                completionHandler(response == .alertFirstButtonReturn ? input.stringValue : nil)
            }
        } else {
            let response = alert.runModal()
            completionHandler(response == .alertFirstButtonReturn ? input.stringValue : nil)
        }
    }
}
