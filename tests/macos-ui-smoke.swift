// Native same-job graphical probe. AX is observation only; every click is CGEvent.
import AppKit
import ApplicationServices
import Foundation

struct Refusal: Error { let message: String }
let deadline = Date().addingTimeInterval(120)
let bundleID = "dev.cornidog.steamos-nvidia-image-builder"
var owned: NSRunningApplication?
var events: [[String: Any]] = []
var out: URL?

func record(_ kind: String, _ fields: [String: Any] = [:]) {
    var row = fields
    row["kind"] = kind
    row["time"] = Date().timeIntervalSince1970
    events.append(row)
    // Persist before any subsequent click/failure so outer cleanup retains PID custody.
    if let out = out, let data = try? JSONSerialization.data(withJSONObject: events, options: [.prettyPrinted, .sortedKeys]) {
        try? data.write(to: out.appendingPathComponent("gui-events.json"), options: .atomic)
    }
}
func require(_ ok: Bool, _ message: String) throws {
    if !ok { throw Refusal(message: message) }
}
func pause() throws {
    try require(Date() < deadline, "absolute GUI deadline")
    RunLoop.current.run(until: Date().addingTimeInterval(0.2))
}
func value(_ element: AXUIElement, _ attribute: String) -> CFTypeRef? {
    var result: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, attribute as CFString, &result) == .success ? result : nil
}
func text(_ element: AXUIElement, _ attribute: String) -> String {
    return value(element, attribute) as? String ?? ""
}
func find(_ root: AXUIElement, _ predicate: (AXUIElement) -> Bool) throws -> AXUIElement? {
    var queue = [root]
    var count = 0
    while !queue.isEmpty {
        try require(Date() < deadline && count < 6000, "AX tree/time bound")
        let element = queue.removeFirst()
        count += 1
        if predicate(element) { return element }
        queue.append(contentsOf: value(element, kAXChildrenAttribute) as? [AXUIElement] ?? [])
    }
    return nil
}
func bounds(_ element: AXUIElement) throws -> CGRect {
    var p = CGPoint.zero
    var s = CGSize.zero
    guard let pv = value(element, kAXPositionAttribute), let sv = value(element, kAXSizeAttribute),
          CFGetTypeID(pv) == AXValueGetTypeID(), CFGetTypeID(sv) == AXValueGetTypeID() else {
        throw Refusal(message: "missing actual AX geometry")
    }
    try require(AXValueGetValue(pv as! AXValue, .cgPoint, &p) &&
                AXValueGetValue(sv as! AXValue, .cgSize, &s), "invalid AX geometry")
    let rect = CGRect(origin: p, size: s)
    try require(rect.width > 0 && rect.height > 0 && CGDisplayBounds(CGMainDisplayID()).contains(rect),
                "control outside active main display")
    return rect
}
func screenshot(_ name: String) throws {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
    p.arguments = ["-x", out!.appendingPathComponent(name + ".png").path]
    try p.run()
    while p.isRunning && Date() < deadline { try pause() }
    if p.isRunning { p.terminate(); p.waitUntilExit(); throw Refusal(message: "screenshot timeout") }
    try require(p.terminationStatus == 0, "screen capture refused")
    let url = out!.appendingPathComponent(name + ".png")
    guard let image = NSImage(contentsOf: url) else { throw Refusal(message: "invalid screenshot pixels") }
    try require(image.size.width > 100 && image.size.height > 100, "empty screenshot")
    record("screenshot", ["name": url.lastPathComponent, "width": image.size.width, "height": image.size.height])
}
func click(_ element: AXUIElement, _ label: String, double: Bool = false) throws {
    try require((value(element, kAXEnabledAttribute) as? Bool) != false, "disabled control: " + label)
    let rect = try bounds(element)
    let point = CGPoint(x: rect.midX, y: rect.midY)
    var pid: pid_t = 0
    AXUIElementGetPid(element, &pid)
    var hit: AXUIElement?
    try require(AXUIElementCopyElementAtPosition(AXUIElementCreateSystemWide(), Float(point.x),
                Float(point.y), &hit) == .success && hit != nil, "control not hittable")
    var hitPID: pid_t = 0
    AXUIElementGetPid(hit!, &hitPID)
    try require(hitPID == pid, "another process occludes " + label)
    let before = CGEvent(source: nil)!.location
    CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: point,
            mouseButton: .left)!.post(tap: .cghidEventTap)
    try pause()
    let after = CGEvent(source: nil)!.location
    try require(abs(after.x-point.x) < 3 && abs(after.y-point.y) < 3, "pointer motion not observed")
    try screenshot(label + "-hover")
    for n in 1...(double ? 2 : 1) {
        for type in [CGEventType.leftMouseDown, CGEventType.leftMouseUp] {
            let event = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: point, mouseButton: .left)!
            event.setIntegerValueField(.mouseEventClickState, value: Int64(n))
            event.post(tap: .cghidEventTap)
        }
    }
    record("pointer-click", ["label": label, "pid": pid, "x": point.x, "y": point.y,
                             "beforeX": before.x, "beforeY": before.y, "observedX": after.x, "observedY": after.y])
}

var failed = false
do {
    try require(CommandLine.arguments.count == 3, "app and output paths required")
    let appURL = URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL
    out = URL(fileURLWithPath: CommandLine.arguments[2])
    let plist = appURL.appendingPathComponent("Contents/Info.plist")
    let info = try PropertyListSerialization.propertyList(from: Data(contentsOf: plist), format: nil) as? [String: Any]
    try require(info?["CFBundleIdentifier"] as? String == bundleID, "wrong input bundle identity")
    try require(NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).isEmpty,
                "pre-existing app: no ownership, do not interact")
    let ax = AXIsProcessTrusted()
    let post = CGPreflightPostEventAccess()
    let screen = CGPreflightScreenCaptureAccess()
    record("permissions", ["AX": ax, "postEvent": post, "screenCapture": screen,
                           "pid": ProcessInfo.processInfo.processIdentifier,
                           "display": CGMainDisplayID(), "displayBounds": NSStringFromRect(CGDisplayBounds(CGMainDisplayID()))])
    try require(ax && post && screen, "GUI permissions unavailable; no TCC bypass")
    try screenshot("desktop-before")
    // Reveal only. Finder must launch the actual app via a real icon double-click.
    NSWorkspace.shared.selectFile(appURL.path, inFileViewerRootedAtPath: appURL.deletingLastPathComponent().path)
    var icon: AXUIElement?
    while icon == nil {
        guard let finder = NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.finder").first else {
            throw Refusal(message: "Finder unavailable")
        }
        icon = try find(AXUIElementCreateApplication(finder.processIdentifier)) { element in
            let name = text(element, kAXTitleAttribute)
            let role = text(element, kAXRoleAttribute)
            return ["SteamOS NVIDIA Builder", "SteamOS NVIDIA Builder.app"].contains(name) &&
                ["AXImage", "AXButton", "AXCell"].contains(role)
        }
        if icon == nil { try pause() }
    }
    try screenshot("finder-before-launch")
    try click(icon!, "finder-app", double: true)
    while owned == nil {
        if let app = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).first {
            // A foreign app with the same identifier never becomes an owned target.
            try require(app.bundleURL?.standardizedFileURL == appURL, "launched wrong bundle path")
            try require((app.launchDate ?? .distantPast) > deadline.addingTimeInterval(-120), "app predates owned transaction")
            owned = app
            record("app", ["pid": app.processIdentifier, "bundle": appURL.path,
                           "executable": app.executableURL?.path ?? "", "architecture": app.executableArchitecture,
                           "launchDate": app.launchDate?.timeIntervalSince1970 ?? 0])
        } else { try pause() }
    }
    let root = AXUIElementCreateApplication(owned!.processIdentifier)
    func button(_ label: String) throws -> AXUIElement? {
        return try find(root) { e in text(e, kAXRoleAttribute) == "AXButton" &&
            [text(e, kAXTitleAttribute), text(e, kAXDescriptionAttribute)].contains(label) }
    }
    var open: AXUIElement?
    while open == nil { open = try button("Open settings"); if open == nil { try pause() } }
    let windows = value(root, kAXWindowsAttribute) as? [AXUIElement] ?? []
    try require(windows.contains { text($0, kAXTitleAttribute) == "SteamOS NVIDIA Builder" }, "main window missing")
    try require(!windows.contains { text($0, kAXTitleAttribute).contains("Opening SteamOS") }, "splash still open")
    record("main-window", ["titles": windows.map { text($0, kAXTitleAttribute) }])
    try screenshot("main-before-settings")
    try click(open!, "open-settings")
    var close: AXUIElement?
    while close == nil { close = try button("Close settings"); if close == nil { try pause() } }
    try screenshot("settings-open")
    record("settings-open-observed")
    try click(close!, "close-settings")
    while try button("Close settings") != nil { try pause() }
    try screenshot("settings-closed")
    record("settings-closed-observed")
    guard let window = (value(root, kAXWindowsAttribute) as? [AXUIElement])?.first,
          let closeWindow = value(window, kAXCloseButtonAttribute) else {
        throw Refusal(message: "normal window close control unavailable")
    }
    try click(closeWindow as! AXUIElement, "close-app")
    while !owned!.isTerminated { try pause() }
    record("normal-app-close", ["terminated": true])
} catch {
    failed = true
    record("failure", ["error": String(describing: error)])
}
// Independently close only the exact new process; forced cleanup never passes.
if let app = owned, !app.isTerminated {
    failed = true
    record("cleanup-terminate", ["accepted": app.terminate()])
    let cleanupEnd = Date().addingTimeInterval(5)
    while !app.isTerminated && Date() < cleanupEnd { RunLoop.current.run(until: Date().addingTimeInterval(0.1)) }
    if !app.isTerminated { record("cleanup-force", ["accepted": app.forceTerminate()]) }
    let forceEnd = Date().addingTimeInterval(5)
    while !app.isTerminated && Date() < forceEnd { RunLoop.current.run(until: Date().addingTimeInterval(0.1)) }
    record("cleanup-closure", ["terminated": app.isTerminated])
}
if let out = out, let data = try? JSONSerialization.data(withJSONObject: events, options: [.prettyPrinted, .sortedKeys]) {
    try? data.write(to: out.appendingPathComponent("gui-events.json"))
}
exit(failed ? 1 : 0)
