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
func guiWaitTick() throws {
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
func find(_ root: AXUIElement, unique: Bool = false, _ predicate: (AXUIElement) -> Bool) throws -> AXUIElement? {
    var queue = [root]
    var count = 0
    var matches: [AXUIElement] = []
    while !queue.isEmpty {
        try require(Date() < deadline && count < 6000, "AX tree/time bound")
        let element = queue.removeFirst()
        count += 1
        if predicate(element) {
            if !unique { return element }
            matches.append(element)
            record("target-candidate", describeTarget(element))
        }
        queue.append(contentsOf: value(element, kAXChildrenAttribute) as? [AXUIElement] ?? [])
    }
    try require(matches.count <= 1, "ambiguous accessible target; no first-match click")
    return matches.first
}
func describeTarget(_ element: AXUIElement) -> [String: Any] {
    var current: AXUIElement? = element
    var ancestry: [[String: Any]] = []
    for _ in 0..<12 {
        guard let node = current else { break }
        var pid: pid_t = 0
        AXUIElementGetPid(node, &pid)
        let enabled: Any = (value(node, kAXEnabledAttribute) as? Bool).map { $0 as Any } ?? "unknown"
        ancestry.append(["role": text(node, kAXRoleAttribute), "title": text(node, kAXTitleAttribute),
            "description": text(node, kAXDescriptionAttribute), "identifier": text(node, kAXIdentifierAttribute),
            "pid": pid, "enabled": enabled])
        guard let parent = value(node, kAXParentAttribute), CFGetTypeID(parent) == AXUIElementGetTypeID() else { break }
        current = (parent as! AXUIElement)
    }
    return ["ancestry": ancestry]
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
    record("measured-control-geometry", ["rect": NSStringFromRect(rect),
        "display": NSStringFromRect(CGDisplayBounds(CGMainDisplayID()))])
    try require(rect.width > 0 && rect.height > 0 && CGDisplayBounds(CGMainDisplayID()).contains(rect),
                "control outside active main display")
    return rect
}
func settledGeometry(_ element: AXUIElement) throws -> CGRect {
    var previous: CGRect?
    while Date() < deadline {
        do {
            let current = try bounds(element)
            if previous == current { return current }
            previous = current
        } catch {
            record("geometry-not-ready", ["error": String(describing: error)])
            previous = nil
        }
        try guiWaitTick()
    }
    throw Refusal(message: "target geometry never settled inside actual display")
}
func screenshot(_ name: String) throws {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
    p.arguments = ["-x", out!.appendingPathComponent(name + ".png").path]
    try p.run()
    while p.isRunning && Date() < deadline { try guiWaitTick() }
    if p.isRunning { p.terminate(); p.waitUntilExit(); throw Refusal(message: "screenshot timeout") }
    try require(p.terminationStatus == 0, "screen capture refused")
    let url = out!.appendingPathComponent(name + ".png")
    guard let image = NSImage(contentsOf: url) else { throw Refusal(message: "invalid screenshot pixels") }
    try require(image.size.width > 100 && image.size.height > 100, "empty screenshot")
    record("screenshot", ["name": url.lastPathComponent, "width": image.size.width, "height": image.size.height])
}
func click(_ element: AXUIElement, _ label: String, double: Bool = false) throws {
    try require((value(element, kAXEnabledAttribute) as? Bool) == true, "disabled or unknown enabled state: " + label)
    let rect = try settledGeometry(element)
    let point = CGPoint(x: rect.midX, y: rect.midY)
    var pid: pid_t = 0
    AXUIElementGetPid(element, &pid)
    func requireExactHit() throws {
        var hit: AXUIElement?
        try require(AXUIElementCopyElementAtPosition(AXUIElementCreateSystemWide(), Float(point.x),
                    Float(point.y), &hit) == .success && hit != nil, "control not hittable")
        var hitPID: pid_t = 0
        AXUIElementGetPid(hit!, &hitPID)
        try require(hitPID == pid, "another process occludes " + label)
        for _ in 0..<32 {
            guard let current = hit else { break }
            if CFEqual(current, element) { return }
            guard let parent = value(current, kAXParentAttribute), CFGetTypeID(parent) == AXUIElementGetTypeID() else { break }
            hit = (parent as! AXUIElement)
        }
        throw Refusal(message: "same-process overlay or unrelated hit target: " + label)
    }
    try requireExactHit()
    let before = CGEvent(source: nil)!.location
    CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: point,
            mouseButton: .left)!.post(tap: .cghidEventTap)
    try guiWaitTick()
    let after = CGEvent(source: nil)!.location
    try require(abs(after.x-point.x) < 3 && abs(after.y-point.y) < 3, "pointer motion not observed")
    try screenshot(label + "-hover")
    try require((value(element, kAXEnabledAttribute) as? Bool) == true, "enabled state changed after hover")
    try require(try bounds(element) == rect, "control moved after hover")
    try requireExactHit()
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
    try require(NSWorkspace.shared.selectFile(appURL.path, inFileViewerRootedAtPath: appURL.deletingLastPathComponent().path), "Finder reveal failed")
    var icon: AXUIElement?
    while icon == nil {
        guard let finder = NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.finder").first else {
            throw Refusal(message: "Finder unavailable")
        }
        icon = try find(AXUIElementCreateApplication(finder.processIdentifier)) { element in
            let name = text(element, kAXTitleAttribute)
            let role = text(element, kAXRoleAttribute)
            let fileURL = value(element, kAXURLAttribute) as? URL
            return ["SteamOS NVIDIA Builder", "SteamOS NVIDIA Builder.app"].contains(name) &&
                ["AXImage", "AXButton", "AXCell"].contains(role) &&
                fileURL?.standardizedFileURL == appURL &&
                (value(element, kAXSelectedAttribute) as? Bool) == true
        }
        if icon == nil { try guiWaitTick() }
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
        } else { try guiWaitTick() }
    }
    let root = AXUIElementCreateApplication(owned!.processIdentifier)
    func button(_ label: String) throws -> AXUIElement? {
        return try find(root, unique: true) { e in text(e, kAXRoleAttribute) == "AXButton" &&
            [text(e, kAXTitleAttribute), text(e, kAXDescriptionAttribute)].contains(label) }
    }
    var open: AXUIElement?
    while open == nil { open = try button("Open settings"); if open == nil { try guiWaitTick() } }
    let windows = value(root, kAXWindowsAttribute) as? [AXUIElement] ?? []
    try require(windows.contains { text($0, kAXTitleAttribute) == "SteamOS NVIDIA Builder" }, "main window missing")
    try require(!windows.contains { text($0, kAXTitleAttribute).contains("Opening SteamOS") }, "splash still open")
    record("main-window", ["titles": windows.map { text($0, kAXTitleAttribute) }])
    try screenshot("main-before-settings")
    try click(open!, "open-settings")
    var close: AXUIElement?
    while close == nil { close = try button("Close settings"); if close == nil { try guiWaitTick() } }
    try screenshot("settings-open")
    record("settings-open-observed")
    try click(close!, "close-settings")
    while try button("Close settings") != nil { try guiWaitTick() }
    try screenshot("settings-closed")
    record("settings-closed-observed")
    // The hosted runner has no admitted appliance or recovery image. Exercise
    // the native chooser with real pointer events, then cancel without inventing
    // a successful Build transaction or changing the selected-image state.
    func chooserCancel() throws -> AXUIElement? {
        let windows = value(root, kAXWindowsAttribute) as? [AXUIElement] ?? []
        var candidates: [AXUIElement] = []
        for window in windows {
            if let cancel = try find(window, unique: true, { element in
                text(element, kAXRoleAttribute) == "AXButton" &&
                    [text(element, kAXTitleAttribute), text(element, kAXDescriptionAttribute)].contains("Cancel")
            }) {
                var windowPID: pid_t = 0
                var cancelPID: pid_t = 0
                AXUIElementGetPid(window, &windowPID)
                AXUIElementGetPid(cancel, &cancelPID)
                try require(windowPID == owned!.processIdentifier && cancelPID == owned!.processIdentifier,
                            "file chooser is not owned by the launched app")
                candidates.append(cancel)
            }
        }
        try require(candidates.count <= 1, "ambiguous native chooser Cancel button")
        return candidates.first
    }
    try require(try chooserCancel() == nil, "unexpected chooser before image click")
    var choose: AXUIElement?
    while choose == nil { choose = try button("Choose Image…"); if choose == nil { try guiWaitTick() } }
    try screenshot("main-before-image-chooser")
    try click(choose!, "choose-image")
    var cancel: AXUIElement?
    while cancel == nil { cancel = try chooserCancel(); if cancel == nil { try guiWaitTick() } }
    try screenshot("native-image-chooser-open")
    record("native-image-chooser-observed", ["appPID": owned!.processIdentifier])
    try click(cancel!, "cancel-image-chooser")
    while try chooserCancel() != nil { try guiWaitTick() }
    try screenshot("native-image-chooser-closed")
    record("native-image-chooser-closed-observed")
    guard let window = (value(root, kAXWindowsAttribute) as? [AXUIElement])?.first,
          let closeWindow = value(window, kAXCloseButtonAttribute) else {
        throw Refusal(message: "normal window close control unavailable")
    }
    try click(closeWindow as! AXUIElement, "close-app")
    while !owned!.isTerminated { try guiWaitTick() }
    record("normal-app-close", ["terminated": true])
} catch {
    failed = true
    record("failure", ["error": String(describing: error)])
    // Preserve actual occluding prompts/layout on refusal, without interacting
    // with permission dialogs or forcing a disabled/foreign target.
    if out != nil && CGPreflightScreenCaptureAccess() { try? screenshot("failure-desktop") }
}
// Independently close only the exact new process; forced cleanup never passes.
if let app = owned, !app.isTerminated {
    failed = true
    func stillOwned() -> Bool {
        guard let current = NSRunningApplication(processIdentifier: app.processIdentifier),
              let originalBirth = app.launchDate, let currentBirth = current.launchDate else { return false }
        return currentBirth == originalBirth && current.executableURL == app.executableURL &&
            current.bundleURL == app.bundleURL
    }
    if stillOwned() { record("cleanup-terminate", ["accepted": app.terminate()]) }
    else { record("cleanup-refused", ["reason": "PID birth/executable ownership changed or unavailable"]) }
    let cleanupEnd = Date().addingTimeInterval(5)
    while !app.isTerminated && Date() < cleanupEnd { RunLoop.current.run(until: Date().addingTimeInterval(0.1)) }
    if !app.isTerminated && stillOwned() { record("cleanup-force", ["accepted": app.forceTerminate()]) }
    let forceEnd = Date().addingTimeInterval(5)
    while !app.isTerminated && Date() < forceEnd { RunLoop.current.run(until: Date().addingTimeInterval(0.1)) }
    record("cleanup-closure", ["terminated": app.isTerminated])
}
if let out = out, let data = try? JSONSerialization.data(withJSONObject: events, options: [.prettyPrinted, .sortedKeys]) {
    try? data.write(to: out.appendingPathComponent("gui-events.json"))
}
exit(failed ? 1 : 0)
