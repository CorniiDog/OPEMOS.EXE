// Native same-job graphical probe. AX is observation only; every click is CGEvent.
import AppKit
import ApplicationServices
import Foundation

struct Refusal: Error { let message: String }
let fullStackImage: URL? = CommandLine.arguments.count == 4 ? URL(fileURLWithPath: CommandLine.arguments[3]).standardizedFileURL : nil
let transactionStarted = Date()
let deadline = transactionStarted.addingTimeInterval(fullStackImage == nil ? 120 : 480)
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
func ownedBirth(_ birth: Date?, since start: Date, observed: Date) -> Bool {
    guard let birth = birth else { return false }
    return birth >= start && birth <= observed
}
if CommandLine.arguments == [CommandLine.arguments[0], "--birth-regression"] {
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    for window in [120.0, 480.0] {
        precondition(ownedBirth(start.addingTimeInterval(1), since: start, observed: start.addingTimeInterval(2)))
        precondition(!ownedBirth(nil, since: start, observed: start.addingTimeInterval(window)))
        precondition(!ownedBirth(start.addingTimeInterval(-1), since: start, observed: start.addingTimeInterval(window)))
        precondition(!ownedBirth(start.addingTimeInterval(window + 1), since: start, observed: start.addingTimeInterval(window)))
    }
    print("Owned birth boundaries passed; model only, actual app custody/closure still required")
    exit(0)
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
    try require([3, 4].contains(CommandLine.arguments.count), "app/output and optional exact Documents image paths required")
    let appURL = URL(fileURLWithPath: CommandLine.arguments[1]).standardizedFileURL
    out = URL(fileURLWithPath: CommandLine.arguments[2])
    let plist = appURL.appendingPathComponent("Contents/Info.plist")
    let info = try PropertyListSerialization.propertyList(from: Data(contentsOf: plist), format: nil) as? [String: Any]
    try require(info?["CFBundleIdentifier"] as? String == bundleID, "wrong input bundle identity")
    guard let executableName = info?["CFBundleExecutable"] as? String,
          !executableName.isEmpty, !executableName.contains("/"), ![".", ".."].contains(executableName) else {
        throw Refusal(message: "invalid bundle executable identity")
    }
    let expectedExecutable = appURL.appendingPathComponent("Contents/MacOS").appendingPathComponent(executableName)
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
    let launchNotBefore = Date()
    record("launch-not-before", ["timeBoundary": launchNotBefore.timeIntervalSince1970,
                                 "transactionStarted": transactionStarted.timeIntervalSince1970,
                                 "deadline": deadline.timeIntervalSince1970])
    try click(icon!, "finder-app", double: true)
    while owned == nil {
        if let app = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).first {
            // A foreign app with the same identifier never becomes an owned target.
            try require(app.bundleURL?.standardizedFileURL == appURL, "launched wrong bundle path")
            try require(app.executableURL?.standardizedFileURL == expectedExecutable, "launched wrong executable path")
            let observed = Date()
            let observedBirth: Any = app.launchDate.map { $0.timeIntervalSince1970 as Any } ?? "unknown"
            record("birth-observed", ["pid": app.processIdentifier,
                "launchDate": observedBirth,
                "notBefore": launchNotBefore.timeIntervalSince1970, "observed": observed.timeIntervalSince1970,
                "bundle": app.bundleURL?.path ?? "unknown", "executable": app.executableURL?.path ?? "unknown"])
            try require(ownedBirth(app.launchDate, since: transactionStarted, observed: observed),
                        "app birth unavailable or outside observed owned launch window")
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
    if let image = fullStackImage {
        let documents = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Documents").standardizedFileURL
        try require(image.deletingLastPathComponent() == documents &&
                    FileManager.default.fileExists(atPath: image.path), "full-stack input must be the admitted exact Documents file")
        // Navigate with actual sidebar and file-cell clicks. No AX value writes,
        // keyboard path shortcuts, direct selection invocation or hidden state.
        if let documentsControl = try find(root, unique: true, { element in
            ["AXRow", "AXButton"].contains(text(element, kAXRoleAttribute)) &&
            [text(element, kAXTitleAttribute), text(element, kAXDescriptionAttribute)].contains("Documents")
        }) { try click(documentsControl, "chooser-documents") }
        var fileCell: AXUIElement?
        let selectionEnd = Date().addingTimeInterval(15)
        while fileCell == nil && Date() < selectionEnd {
            fileCell = try find(root, unique: true) { element in
                let file = value(element, kAXURLAttribute) as? URL
                return ["AXCell", "AXRow", "AXImage"].contains(text(element, kAXRoleAttribute)) &&
                    file?.standardizedFileURL == image
            }
            if fileCell == nil { try guiWaitTick() }
        }
        guard let fileCell = fileCell else { throw Refusal(message: "exact admitted file URL not visibly selectable in native chooser") }
        try click(fileCell, "choose-pinned-image", double: true)
        while try chooserCancel() != nil { try guiWaitTick() }
        record("native-image-selected-observed", ["path": image.path])
        try screenshot("pinned-image-selected")
        var build: AXUIElement?
        while build == nil {
            if let candidate = try button("Build NVIDIA Image"),
               (value(candidate, kAXEnabledAttribute) as? Bool) == true { build = candidate }
            else { try guiWaitTick() }
        }
        try click(build!, "build-pinned-image")
        var observedHashing = false
        var observedReady = false
        var observedHealth = false
        var observedNext = false
        var nextCapture = Date.distantPast
        while !observedNext {
            var strings: [String] = []
            _ = try find(root) { element in
                for attribute in [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute] {
                    let string = text(element, attribute)
                    if !string.isEmpty { strings.append(string) }
                }
                return false
            }
            let visible = strings.joined(separator: "\n")
            observedHashing = observedHashing || visible.contains("Hashing") || visible.contains("hashing")
            observedReady = observedReady || visible.contains("STEAMOS_BUILDER_READY received.")
            observedHealth = observedHealth || visible.contains("Health: protocol 1;")
            observedNext = visible.contains("Selected image:")
            if Date() >= nextCapture {
                record("visible-build-state", ["text": String(visible.prefix(65536)),
                    "hashing": observedHashing, "ready": observedReady, "health": observedHealth, "nextStage": observedNext])
                try screenshot("build-" + String(events.count))
                nextCapture = Date().addingTimeInterval(10)
            }
            if visible.contains("Build failed") || visible.contains("timed out") || visible.contains("timedOut") {
                throw Refusal(message: "actual Build failure; retained visible text and screenshot")
            }
            if !observedNext { try guiWaitTick() }
        }
        try require(observedHashing && observedReady && observedHealth,
                    "next stage lacks observed hashing, cold readiness or guest health")
        record("cold-build-next-stage-observed", ["outputAcceptance": false])
        guard let cancelBuild = try button("Cancel Build") else { throw Refusal(message: "normal cancel control missing") }
        try click(cancelBuild, "cancel-after-next-stage")
        var closeProgress: AXUIElement?
        while closeProgress == nil { closeProgress = try button("Close"); if closeProgress == nil { try guiWaitTick() } }
        try screenshot("cancelled-build")
        try click(closeProgress!, "close-build-progress")
    } else {
        try click(cancel!, "cancel-image-chooser")
        while try chooserCancel() != nil { try guiWaitTick() }
        try screenshot("native-image-chooser-closed")
        record("native-image-chooser-closed-observed")
    }
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
