import AppKit
import Foundation
import UniformTypeIdentifiers

@main
final class RustorrentLauncher: NSObject, NSApplicationDelegate {
    private let uiPort = 9473
    private let maxUiWaitAttempts = 150
    private let openUiOnLaunchKey = "open_ui_on_launch"
    private let downloadDirectoryKey = "download_directory"

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

    static func main() {
        let app = NSApplication.shared
        let delegate = RustorrentLauncher()
        app.delegate = delegate
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        buildMenus()
        collectStartupTorrentFiles(from: CommandLine.arguments)
        openUiWhenReady = openUiOnLaunchEnabled() || !pendingTorrentFiles.isEmpty

        if isUiReachable(timeout: 0.8) {
            flushPendingTorrents()
            if openUiWhenReady {
                openWebUi()
            }
        } else {
            startBackendIfNeeded()
            waitForUiReady()
        }

        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openUiWhenReady = true
        openWebUi()
        return true
    }

    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        enqueueTorrentFiles(from: filenames)
        openUiWhenReady = true
        if isUiReachable(timeout: 0.6) {
            flushPendingTorrents()
            openWebUi()
        } else {
            startBackendIfNeeded()
            waitForUiReady()
        }
        sender.reply(toOpenOrPrint: .success)
    }

    func applicationWillTerminate(_ notification: Notification) {
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
            checkboxWithTitle: "Open Web UI when launching Rustorrent",
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

        let launchNow = NSButton(title: "Launch UI Now", target: self, action: #selector(openWebUiFromMenu))
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
        if isUiReachable(timeout: 0.6) {
            openWebUi()
        } else {
            startBackendIfNeeded()
            waitForUiReady()
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
            if self.isUiReachable(timeout: 0.6) {
                self.flushPendingTorrents()
                self.openWebUi()
            } else {
                self.startBackendIfNeeded()
                self.waitForUiReady()
            }
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

        let launchUi = NSMenuItem(title: "Launch Web UI", action: #selector(openWebUiFromMenu), keyEquivalent: "l")
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

        let fileLaunch = NSMenuItem(title: "Launch Web UI", action: #selector(openWebUiFromMenu), keyEquivalent: "l")
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
            logHandle = try FileHandle(forWritingTo: logFile)
            logHandle?.seekToEndOfFile()
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
                timer.invalidate()
                self.uiReadyTimer = nil
                self.flushPendingTorrents()
                if self.openUiWhenReady {
                    self.openWebUi()
                }
                return
            }
            if self.uiWaitAttempts >= self.maxUiWaitAttempts {
                timer.invalidate()
                self.uiReadyTimer = nil
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
        if !NSWorkspace.shared.open(url) {
            let opener = Process()
            opener.executableURL = URL(fileURLWithPath: "/usr/bin/open")
            opener.arguments = [url.absoluteString]
            try? opener.run()
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
}
