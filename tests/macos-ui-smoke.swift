// Native same-job graphical probe. AX is observation only; every click is CGEvent.
import AppKit
import ApplicationServices
import Foundation
import Security
import Darwin

struct Refusal: Error { let message: String }
let chooserDiagnostic = CommandLine.arguments.count == 5 && CommandLine.arguments[4] == "--chooser-diagnostic"
let fullStackImage: URL? = [4, 5].contains(CommandLine.arguments.count) ? URL(fileURLWithPath: CommandLine.arguments[3]).standardizedFileURL : nil
let transactionStarted = Date()
let deadline = transactionStarted.addingTimeInterval(chooserDiagnostic || fullStackImage == nil ? 120 : 480)
let bundleID = "dev.cornidog.steamos-nvidia-image-builder"
var owned: NSRunningApplication?
var events: [[String: Any]] = []
var out: URL?
let panelServiceID = "com.apple.appkit.xpc.openAndSavePanelService"
var chooserRequestedAt: Date?
var delegatedPanel: AXUIElement?
var delegatedWindow: AXUIElement?
var delegatedPID: pid_t?
var delegatedBirth: Date?
var evidenceWriteFailed = false
var fallbackBytes = 0
var pairSequence = 0
var pendingPairs: Set<Int> = []
var helperBirth: String?

// Native OS observations, not an ancestry-only or label-based PID exemption.
func nativeActor(_ pid: pid_t) throws -> (app: NSRunningApplication?, uid: uid_t?, valid: Bool) {
    try require(Date() < deadline && pid > 0, "invalid native actor/deadline")
    let before = NSRunningApplication(processIdentifier: pid)
    let probe = Process()
    let pipe = Pipe()
    probe.executableURL = URL(fileURLWithPath: "/bin/ps")
    probe.arguments = ["-p", String(pid), "-o", "uid="]
    probe.standardOutput = pipe
    probe.standardError = FileHandle.nullDevice
    try probe.run()
    let end = min(deadline, Date().addingTimeInterval(2))
    while probe.isRunning && Date() < end { RunLoop.current.run(until: Date().addingTimeInterval(0.01)) }
    if probe.isRunning { probe.terminate(); probe.waitUntilExit(); throw Refusal(message: "native UID probe timed out") }
    probe.waitUntilExit()
    let uidText = String(data: pipe.fileHandleForReading.readData(ofLength: 64), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let uid = probe.terminationStatus == 0 ? UInt32(uidText) : nil
    var code: SecCode?
    let guestStatus = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary,
                                                    SecCSFlags(rawValue: 0), &code)
    var requirement: SecRequirement?
    let requirementStatus = SecRequirementCreateWithString(("anchor apple and identifier \"" + panelServiceID + "\"") as CFString,
                                                           SecCSFlags(rawValue: 0), &requirement)
    var signing: CFDictionary?
    var signingStatus: OSStatus = errSecParam
    var validity: OSStatus = errSecParam
    var staticStatus: OSStatus = errSecParam
    var codePath: CFURL?
    if let code = code {
        if requirementStatus == errSecSuccess, let requirement = requirement {
            validity = SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement)
        }
        // Swift's metadata/path APIs take SecStaticCode; dynamic validation
        // above still binds the running PID. CodeCopyPath is the bundle path.
        var staticCode: SecStaticCode?
        staticStatus = SecCodeCopyStaticCode(code, SecCSFlags(rawValue: 0), &staticCode)
        if let staticCode = staticCode {
            signingStatus = SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &signing)
            _ = SecCodeCopyPath(staticCode, SecCSFlags(rawValue: 0), &codePath)
        }
    }
    let info = signing as? [String: Any] ?? [:]
    let after = NSRunningApplication(processIdentifier: pid)
    let stable = before?.launchDate != nil && before?.launchDate == after?.launchDate &&
        before?.executableURL == after?.executableURL && before?.bundleURL == after?.bundleURL && after?.isTerminated == false
    record("native-chooser-actor", ["pid": pid, "uid": uid.map { $0 as Any } ?? "unknown",
        "uidProbePID": probe.processIdentifier, "uidProbeExit": probe.terminationStatus,
        "birth": after?.launchDate?.timeIntervalSince1970 ?? -1,
        "bundle": after?.bundleURL?.path ?? "unknown", "identifier": after?.bundleIdentifier ?? "unknown",
        "executable": after?.executableURL?.path ?? "unknown", "codePath": codePath.map { ($0 as URL).path } ?? "unknown",
        "signingIdentifier": info[kSecCodeInfoIdentifier as String] as? String ?? "unknown",
        "guestStatus": guestStatus, "staticStatus": staticStatus, "signingStatus": signingStatus, "requirementStatus": requirementStatus,
        "appleServiceValidity": validity, "stableBeforeAfter": stable])
    let executable = after?.executableURL?.resolvingSymlinksInPath()
    let bundle = after?.bundleURL?.resolvingSymlinksInPath()
    let systemLocation = bundle?.path.hasPrefix("/System/Library/Frameworks/AppKit.framework/Versions/") == true &&
        bundle?.lastPathComponent == panelServiceID + ".xpc" && bundle?.deletingLastPathComponent().lastPathComponent == "XPCServices"
    let metadata = bundle.flatMap { Bundle(url: $0) }
    let signedExecutable = (info[kSecCodeInfoMainExecutable as String] as? URL)?.resolvingSymlinksInPath()
    let executableName = metadata?.object(forInfoDictionaryKey: "CFBundleExecutable") as? String
    let exactExecutable = executableName.map { !$0.isEmpty && !$0.contains("/") && $0 != "." && $0 != ".." &&
        executable == bundle?.appendingPathComponent("Contents/MacOS").appendingPathComponent($0) } ?? false
    record("native-chooser-system-location", ["pid": pid, "systemLocation": systemLocation,
        "bundleExecutable": executableName ?? "unknown", "exactExecutable": exactExecutable,
        "signedExecutable": signedExecutable?.path ?? "unknown",
        "bundleIdentifier": metadata?.bundleIdentifier ?? "unknown"])
    return (after, uid, stable && uid == getuid() && guestStatus == errSecSuccess && signingStatus == errSecSuccess &&
        validity == errSecSuccess && systemLocation && exactExecutable && after?.bundleIdentifier == panelServiceID &&
        staticStatus == errSecSuccess && signedExecutable == executable &&
        (info[kSecCodeInfoIdentifier as String] as? String) == panelServiceID && codePath.map { ($0 as URL).resolvingSymlinksInPath() } == bundle)
}

func requireCurrentApp() throws -> NSRunningApplication {
    guard let original = owned, let current = NSRunningApplication(processIdentifier: original.processIdentifier),
          !current.isTerminated, current.launchDate != nil, current.launchDate == original.launchDate,
          current.executableURL == original.executableURL, current.bundleURL == original.bundleURL else {
        throw Refusal(message: "owned app PID/birth/executable changed")
    }
    return current
}

func panelAncestors(_ element: AXUIElement) -> (AXUIElement?, AXUIElement?) {
    var node: AXUIElement? = element
    var panel: AXUIElement?
    var window: AXUIElement?
    for _ in 0..<32 {
        guard let current = node else { break }
        if text(current, kAXRoleAttribute) == "AXSheet" { panel = current }
        if text(current, kAXRoleAttribute) == "AXWindow" { window = current }
        guard let parent = value(current, kAXParentAttribute), CFGetTypeID(parent) == AXUIElementGetTypeID() else { break }
        node = (parent as! AXUIElement)
    }
    return (panel, window)
}

func requireControlCustody(_ element: AXUIElement) throws {
    guard owned != nil else { return } // Finder launch is separately exact-URL bound.
    let app = try requireCurrentApp()
    var pid: pid_t = 0
    try require(AXUIElementGetPid(element, &pid) == .success, "unknown native control PID")
    if pid == app.processIdentifier { return }
    guard let panel = delegatedPanel, let window = delegatedWindow,
          let actorPID = delegatedPID, pid == actorPID, let birth = delegatedBirth,
          chooserRequestedAt != nil else { throw Refusal(message: "unbound different-PID native control") }
    let (currentPanel, currentWindow) = panelAncestors(element)
    try require(currentPanel.map { CFEqual($0, panel) } == true && currentWindow.map { CFEqual($0, window) } == true,
                "native actor control is outside the exact delegated panel")
    let windows = value(AXUIElementCreateApplication(app.processIdentifier), kAXWindowsAttribute) as? [AXUIElement] ?? []
    try require(windows.contains { CFEqual($0, window) }, "delegated panel window no longer belongs to current app")
    let actor = try nativeActor(pid)
    try require(actor.valid && actor.app?.launchDate == birth, "native delegated actor changed, foreign or unverified")
}

func bindChooser(_ element: AXUIElement, window: AXUIElement) throws {
    let app = try requireCurrentApp()
    var pid: pid_t = 0
    var windowPID: pid_t = 0
    AXUIElementGetPid(element, &pid)
    AXUIElementGetPid(window, &windowPID)
    try require(windowPID == app.processIdentifier, "foreign native chooser window")
    if pid == app.processIdentifier { return }
    let actor = try nativeActor(pid) // Persist actual missing/denied facts before refusal.
    let (panel, parentWindow) = panelAncestors(element)
    guard chooserRequestedAt != nil, let panel = panel, let parentWindow = parentWindow,
          CFEqual(parentWindow, window), let birth = actor.app?.launchDate,
          let appBirth = app.launchDate else { throw Refusal(message: "native chooser delegation facts unavailable") }
    var panelPID: pid_t = 0
    AXUIElementGetPid(panel, &panelPID)
    record("native-chooser-binding-observed", ["appPID": app.processIdentifier, "windowPID": windowPID,
        "actorPID": pid, "panelPID": panelPID, "actorBirth": birth.timeIntervalSince1970,
        "appBirth": appBirth.timeIntervalSince1970, "requestedAt": chooserRequestedAt!.timeIntervalSince1970,
        "actorIdentityQualified": actor.valid])
    try require(actor.valid && birth >= appBirth && panelPID == app.processIdentifier,
                "native chooser actor OS identity or new app/panel delegation unverified")
    if let old = delegatedPID { try require(old == pid && delegatedBirth == birth, "native chooser actor unexpectedly replaced") }
    delegatedPID = pid; delegatedBirth = birth; delegatedPanel = panel; delegatedWindow = window
    try requireControlCustody(element)
    record("native-chooser-delegation-bound", ["appPID": app.processIdentifier, "actorPID": pid,
        "actorBirth": birth.timeIntervalSince1970, "requestedAt": chooserRequestedAt!.timeIntervalSince1970])
}

func record(_ kind: String, _ fields: [String: Any] = [:]) {
    var row = fields
    row["kind"] = kind
    row["time"] = Date().timeIntervalSince1970
    events.append(row)
    // Persist before any subsequent click/failure so outer cleanup retains PID custody.
    if let out = out {
        do {
            let data = try JSONSerialization.data(withJSONObject: events, options: [.prettyPrinted, .sortedKeys])
            try require(data.count <= 2 * 1024 * 1024, "GUI evidence bound exceeded")
            let path = out.appendingPathComponent("gui-events.json")
            try data.write(to: path, options: .atomic)
            let handle = try FileHandle(forWritingTo: path)
            defer { try? handle.close() }
            try handle.synchronize()
        } catch {
            if (!evidenceWriteFailed || fields["error"] != nil) && fallbackBytes < 4096 {
                let message = "GUI_EVIDENCE_WRITE_FAILED kind=" + kind + " original=" +
                    String(describing: fields["error"] ?? "none") + " persistence=" + String(describing: error)
                let data = Data((String(message.prefix(min(1024, 4096 - fallbackBytes))) + "\n").utf8)
                FileHandle.standardError.write(data); fallbackBytes += data.count
            }
            evidenceWriteFailed = true
        }
    }
}
func require(_ ok: Bool, _ message: String) throws {
    if !ok { throw Refusal(message: message) }
}
func prepareActualDisplay() throws {
    let display = CGMainDisplayID()
    let modes = CGDisplayCopyAllDisplayModes(display, nil) as? [CGDisplayMode] ?? []
    record("supported-display-modes", ["display": display, "modes": modes.map {
        ["width": $0.width, "height": $0.height, "pixelWidth": $0.pixelWidth, "pixelHeight": $0.pixelHeight]
    }])
    guard let mode = modes.first(where: {
        $0.width == 1600 && $0.height == 900 && $0.pixelWidth == 1600 && $0.pixelHeight == 900
    }) else { throw Refusal(message: "No actual supported unscaled 1600x900 display mode") }
    let result = CGDisplaySetDisplayMode(display, mode, nil)
    record("display-mode-set", ["result": result.rawValue, "display": display])
    try require(result == .success, "native 1600x900 mode change refused")
    // Observe the real display after the native mode call, never viewer scaling.
    let bounds = CGDisplayBounds(display)
    record("actual-display-1600x900", ["width": CGDisplayPixelsWide(display),
        "height": CGDisplayPixelsHigh(display), "bounds": NSStringFromRect(bounds),
        "screens": NSScreen.screens.map { ["frame": NSStringFromRect($0.frame),
                                            "usableFrame": NSStringFromRect($0.visibleFrame)] }])
    try require(CGDisplayPixelsWide(display) == 1600 && CGDisplayPixelsHigh(display) == 900 &&
                bounds.width == 1600 && bounds.height == 900, "actual display mode does not match 1600x900")
}
func ownedBirth(_ birth: Date?, since start: Date, observed: Date) -> Bool {
    guard let birth = birth else { return false }
    return birth >= start && birth <= observed
}
func nativeFilePath(_ file: URL?) -> URL? {
    guard let file = file, file.isFileURL,
          let path = (file as NSURL).filePathURL,
          FileManager.default.fileExists(atPath: path.path) else { return nil }
    return path.standardizedFileURL
}
if CommandLine.arguments == [CommandLine.arguments[0], "--birth-regression"] {
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    for window in [120.0, 480.0] {
        precondition(ownedBirth(start.addingTimeInterval(1), since: start, observed: start.addingTimeInterval(2)))
        precondition(!ownedBirth(nil, since: start, observed: start.addingTimeInterval(window)))
        precondition(!ownedBirth(start.addingTimeInterval(-1), since: start, observed: start.addingTimeInterval(window)))
        precondition(!ownedBirth(start.addingTimeInterval(window + 1), since: start, observed: start.addingTimeInterval(window)))
    }
    // Geometry cases only, not a substitute for the actual packaged app below.
    let smallUsable = CGRect(x: 0, y: 25, width: 1024, height: 680)
    precondition(!smallUsable.contains(CGRect(x: 171, y: 714, width: 682, height: 42)))
    precondition(smallUsable.contains(CGRect(x: 171, y: 600, width: 682, height: 42)))
    let actualChooserViewport = CGRect(x: 544, y: 265, width: 245, height: 324)
    let measuredFileRow = CGRect(x: 580, y: 272, width: 169, height: 18)
    precondition(actualChooserViewport.contains(measuredFileRow))
    precondition(!actualChooserViewport.insetBy(dx: 8, dy: 8).contains(measuredFileRow))
    precondition(!actualChooserViewport.contains(CGRect(x: 580, y: 260, width: 169, height: 18)))
    do {
        let directory = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("opemos-file-reference-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("actual-file.img")
        try Data("actual file-reference boundary".utf8).write(to: file, options: .withoutOverwriting)
        guard let reference = (file as NSURL).fileReferenceURL() else {
            throw Refusal(message: "native file-reference creation unavailable")
        }
        try require(nativeFilePath(reference) == file.standardizedFileURL,
                    "file-reference path mismatch expected=\(file.path) observed=\(String(describing: nativeFilePath(reference)))")
        precondition(nativeFilePath(URL(string: "https://example.invalid/")) == nil)
        try FileManager.default.removeItem(at: file)
        precondition(nativeFilePath(reference) == nil)
        print("Actual same-UID file-reference conversion/missing/nonfile cases passed")
    } catch { fatalError("Actual native file-reference boundary failed: \(error)") }
    print("Owned birth boundaries passed; model only, actual app custody/closure still required")
    do {
        let actual = try nativeActor(ProcessInfo.processInfo.processIdentifier)
        precondition(actual.uid == getuid() && !actual.valid) // Our unsigned Swift helper is not the Apple service.
        do { _ = try nativeActor(0); fatalError("invalid PID accepted") } catch {}
        print("Actual UID/process/SecCode non-service and invalidPID negatives passed; no delegated UI authority inferred")
    } catch { fatalError("native actor regression failed: \(error)") }
    guard let source = CGEventSource(stateID: .combinedSessionState),
          let down = CGEvent(mouseEventSource: source, mouseType: .leftMouseDown, mouseCursorPosition: .zero, mouseButton: .left),
          let up = CGEvent(mouseEventSource: source, mouseType: .leftMouseUp, mouseCursorPosition: .zero, mouseButton: .left) else {
        fatalError("Actual native pair construction unavailable")
    }
    up.setIntegerValueField(.mouseEventNumber, value: down.getIntegerValueField(.mouseEventNumber))
    precondition(down.type == .leftMouseDown && up.type == .leftMouseUp &&
                 down.getIntegerValueField(.mouseEventNumber) == up.getIntegerValueField(.mouseEventNumber))
    print("Actual native pair construction/number and state observed (no events posted, no input closure proof): \(inputState())")
    exit(0)
}
func guiWaitTick() throws {
    if let app = owned, app.isTerminated {
        record("owned-app-exited-before-control", ["pid": app.processIdentifier, "numericExit": "unknown"])
        throw Refusal(message: "owned app exited before required graphical transaction")
    }
    try require(Date() < deadline, "absolute GUI deadline")
    RunLoop.current.run(until: Date().addingTimeInterval(0.2))
}
var observedAXErrors = Set<String>()
func value(_ element: AXUIElement, _ attribute: String) -> CFTypeRef? {
    var result: CFTypeRef?
    let error = AXUIElementCopyAttributeValue(element, attribute as CFString, &result)
    if error != .success {
        let key = attribute + ":" + String(error.rawValue)
        if observedAXErrors.insert(key).inserted {
            record("AX-read-error", ["attribute": attribute, "error": error.rawValue])
        }
    }
    return error == .success ? result : nil
}
func text(_ element: AXUIElement, _ attribute: String) -> String {
    return value(element, attribute) as? String ?? ""
}
func find(_ root: AXUIElement, unique: Bool = false, validateCustody: Bool = true, _ predicate: (AXUIElement) -> Bool) throws -> AXUIElement? {
    var queue = [root]
    var count = 0
    var matches: [AXUIElement] = []
    while !queue.isEmpty {
        try require(Date() < deadline && count < 6000, "AX tree/time bound")
        let element = queue.removeFirst()
        count += 1
        if predicate(element) {
            if validateCustody { try requireControlCustody(element) }
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
func observedRect(_ element: AXUIElement) throws -> CGRect {
    var p = CGPoint.zero
    var s = CGSize.zero
    guard let pv = value(element, kAXPositionAttribute), let sv = value(element, kAXSizeAttribute),
          CFGetTypeID(pv) == AXValueGetTypeID(), CFGetTypeID(sv) == AXValueGetTypeID() else {
        throw Refusal(message: "missing actual AX geometry")
    }
    try require(AXValueGetValue(pv as! AXValue, .cgPoint, &p) &&
                AXValueGetValue(sv as! AXValue, .cgSize, &s), "invalid AX geometry")
    return CGRect(origin: p, size: s)
}
func usableDisplayBounds() throws -> CGRect {
    guard let screen = NSScreen.screens.first(where: {
        ($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.uint32Value == CGMainDisplayID()
    }) else { throw Refusal(message: "actual main NSScreen unavailable") }
    let visible = screen.visibleFrame
    // NSScreen is bottom-left; AX/CGEvent use the primary screen's top-left.
    let rect = CGRect(x: visible.minX, y: screen.frame.maxY - visible.maxY,
                      width: visible.width, height: visible.height)
    try require(!rect.isEmpty && CGDisplayBounds(CGMainDisplayID()).contains(rect), "invalid actual usable display bounds")
    return rect
}
func bounds(_ element: AXUIElement) throws -> CGRect {
    try requireControlCustody(element)
    let rect = try observedRect(element)
    record("measured-control-geometry", ["rect": NSStringFromRect(rect),
        "display": NSStringFromRect(CGDisplayBounds(CGMainDisplayID()))])
    try require(rect.width > 0 && rect.height > 0 && CGDisplayBounds(CGMainDisplayID()).contains(rect),
                "control outside active main display")
    return rect
}

struct FileItemCustody {
    let leaf: AXUIElement
    let container: AXUIElement?
    let image: URL
    let window: AXUIElement
}
func axParent(_ element: AXUIElement) -> AXUIElement? {
    guard let p = value(element, kAXParentAttribute), CFGetTypeID(p) == AXUIElementGetTypeID() else { return nil }
    return (p as! AXUIElement)
}
func exactFileLeaves(_ element: AXUIElement) throws -> [AXUIElement] {
    var queue = [element]
    var matches: [AXUIElement] = []
    var visited = 0
    while !queue.isEmpty {
        let node = queue.removeFirst(); visited += 1
        try require(visited <= 64, "file item native inventory bound")
        if value(node, kAXURLAttribute) != nil { matches.append(node); continue }
        guard let children = value(node, kAXChildrenAttribute) as? [AXUIElement] else {
            throw Refusal(message: "file item child inventory unavailable")
        }
        try require(queue.count + children.count <= 64, "file item native child bound")
        queue.append(contentsOf: children)
    }
    return matches
}
func qualifyFileItem(_ leaf: AXUIElement, _ image: URL) throws -> FileItemCustody {
    try requireControlCustody(leaf)
    guard let window = panelAncestors(leaf).1 else { throw Refusal(message: "file item window unavailable") }
    var container: AXUIElement?
    if let parent = axParent(leaf), text(parent, kAXRoleAttribute) == "AXGroup",
       let list = axParent(parent), text(list, kAXRoleAttribute) == "AXList" {
        let urls = (try? exactFileLeaves(parent)) ?? []
        if urls.count == 1 && CFEqual(urls[0], leaf) &&
            nativeFilePath(value(leaf, kAXURLAttribute) as? URL) == image {
            let parentRect = try observedRect(parent)
            let leafRect = try observedRect(leaf)
            if parentRect.contains(leafRect) {
                try requireControlCustody(parent)
                container = parent
            }
        }
    }
    record("file-item-custody", ["uniqueURL": image.path, "containerQualified": container != nil,
        "leaf": describeTarget(leaf), "container": container.map { describeTarget($0) } ?? [:],
        "leafEqualsContainer": container.map { CFEqual(leaf, $0) } ?? false])
    return FileItemCustody(leaf: leaf, container: container, image: image, window: window)
}
func validateFileItem(_ item: FileItemCustody, _ point: CGPoint) throws {
    try requireControlCustody(item.leaf)
    try require(nativeFilePath(value(item.leaf, kAXURLAttribute) as? URL) == item.image,
                "held file URL changed")
    guard let window = panelAncestors(item.leaf).1 else { throw Refusal(message: "held file window missing") }
    try require(CFEqual(window, item.window), "held file window changed")
    if let container = item.container {
        let urls = try exactFileLeaves(container)
        try require(axParent(item.leaf).map { CFEqual($0, container) } == true &&
                    urls.count == 1 && CFEqual(urls[0], item.leaf), "held item identity/unique URL changed")
        try require((try observedRect(container)).contains(point) &&
                    (try actualControlViewport(container).viewport).contains(try observedRect(container)),
                    "held file item clipping changed")
    }
}
func requireExactHit(_ element: AXUIElement, _ point: CGPoint, _ label: String, fileItem: FileItemCustody? = nil) throws {
    try requireControlCustody(element)
    var expectedPID: pid_t = 0
    AXUIElementGetPid(element, &expectedPID)
    var hit: AXUIElement?
    let status = AXUIElementCopyElementAtPosition(AXUIElementCreateSystemWide(), Float(point.x), Float(point.y), &hit)
    var hitPID: pid_t = 0
    if let hit = hit { AXUIElementGetPid(hit, &hitPID) }
    let actor = NSRunningApplication(processIdentifier: hitPID)
    if let item = fileItem { try validateFileItem(item, point) }
    var observed = hit
    var equalities: [[String: Any]] = []
    for _ in 0..<12 {
        guard let node = observed else { break }
        var pid: pid_t = 0
        let pidStatus = AXUIElementGetPid(node, &pid)
        equalities.append(["role": text(node, kAXRoleAttribute), "pid": pid, "pidStatus": pidStatus.rawValue,
            "leafEqual": CFEqual(node, element),
            "containerEqual": fileItem?.container.map { CFEqual(node, $0) } ?? false,
            "windowEqual": fileItem.map { CFEqual(node, $0.window) } ?? false])
        observed = axParent(node)
    }
    record("native-hit-equality", ["label": label, "status": status.rawValue,
        "leafEqual": hit.map { CFEqual($0, element) } ?? false,
        "heldContainerEqual": hit.flatMap { h in fileItem?.container.map { CFEqual(h, $0) } } ?? false,
        "hit": hit.map { describeTarget($0) } ?? [:], "equalityAncestry": equalities])
    record("actual-pointer-hit", ["label": label, "x": point.x, "y": point.y,
        "expectedPID": expectedPID, "hitPID": hitPID, "status": status.rawValue,
        "hitBundle": actor?.bundleIdentifier ?? "unknown", "hitExecutable": actor?.executableURL?.path ?? "unknown",
        "hitBirth": actor?.launchDate?.timeIntervalSince1970 ?? -1,
        "hitRole": hit.map { text($0, kAXRoleAttribute) } ?? "unknown",
        "usableBounds": NSStringFromRect(try usableDisplayBounds())])
    try require(status == .success && hit != nil, "control not hittable")
    try require(hitPID == expectedPID, "another process occludes " + label)
    if let item = fileItem, let container = item.container, let hit = hit, CFEqual(hit, container) {
        try validateFileItem(item, point)
        return
    }
    for _ in 0..<32 {
        guard let current = hit else { break }
        if CFEqual(current, element) { return }
        guard let parent = value(current, kAXParentAttribute), CFGetTypeID(parent) == AXUIElementGetTypeID() else { break }
        hit = (parent as! AXUIElement)
    }
    throw Refusal(message: "same-process overlay or unrelated hit target: " + label)
}

func actualControlViewport(_ element: AXUIElement) throws -> (viewport: CGRect, scroll: AXUIElement?) {
    try requireControlCustody(element)
    var pid: pid_t = 0
    try require(AXUIElementGetPid(element, &pid) == .success, "unknown control owner")
    var ancestor: AXUIElement? = element
    var scroll: AXUIElement?
    var viewport = try usableDisplayBounds()
    for _ in 0..<32 {
        guard let node = ancestor else { break }
        let role = text(node, kAXRoleAttribute)
        if ["AXScrollArea", "AXWindow", "AXSheet"].contains(role) {
            var ancestorPID: pid_t = 0
            try requireControlCustody(node)
            try require(AXUIElementGetPid(node, &ancestorPID) == .success &&
                        (ancestorPID == pid || (pid == delegatedPID && ancestorPID == owned?.processIdentifier)),
                        "foreign or unknown clipping ancestor")
            viewport = viewport.intersection(try observedRect(node))
            if scroll == nil && role == "AXScrollArea" { scroll = node }
        }
        guard let parent = value(node, kAXParentAttribute), CFGetTypeID(parent) == AXUIElementGetTypeID() else { break }
        ancestor = (parent as! AXUIElement)
    }
    try require(!viewport.isEmpty && !viewport.isNull, "no actual visible control viewport")
    return (viewport, scroll)
}
func revealOwnedControl(_ element: AXUIElement, _ label: String) throws {
    var pid: pid_t = 0
    AXUIElementGetPid(element, &pid)
    guard owned != nil else { return }
    try requireControlCustody(element)
    for attempt in 0...8 {
        let (viewport, scroll) = try actualControlViewport(element)
        let rect = try observedRect(element)
        record("actual-scroll-layout", ["label": label, "attempt": attempt,
            "target": NSStringFromRect(rect), "viewport": NSStringFromRect(viewport),
            "display": NSStringFromRect(CGDisplayBounds(CGMainDisplayID()))])
        if viewport.contains(rect) { return }
        guard attempt < 8, let scroll = scroll else { throw Refusal(message: "control unreachable in actual scroll viewport: " + label) }
        try require(rect.minX >= viewport.minX && rect.maxX <= viewport.maxX, "horizontal control clipping: " + label)
        // Scroll margins select a safe gesture point, never redefine the real
        // clipping rectangle (the measured file row was falsely clipped 1px).
        let gestureBounds = viewport.insetBy(dx: min(8, viewport.width / 4), dy: min(8, viewport.height / 4))
        let point = CGPoint(x: gestureBounds.midX, y: gestureBounds.midY)
        try requireExactHit(scroll, point, "scroll-" + label)
        CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: point, mouseButton: .left)!.post(tap: .cghidEventTap)
        try guiWaitTick()
        let observed = CGEvent(source: nil)!.location
        try require(abs(observed.x-point.x) < 3 && abs(observed.y-point.y) < 3, "scroll pointer motion not observed")
        try requireExactHit(scroll, point, "scroll-" + label)
        let delta: Int32 = rect.maxY > viewport.maxY ? -120 : 120
        guard let event = CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 1,
                                  wheel1: delta, wheel2: 0, wheel3: 0) else { throw Refusal(message: "native scroll event unavailable") }
        event.post(tap: .cghidEventTap)
        record("pointer-scroll", ["label": label, "x": point.x, "y": point.y, "delta": delta, "pid": pid])
        try guiWaitTick()
    }
}
func settledGeometry(_ element: AXUIElement) throws -> CGRect {
    var previous: CGRect?
    while Date() < deadline {
        do {
            let current = try bounds(element)
            try require(try actualControlViewport(element).viewport.contains(current), "control clipped by actual viewport")
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
func screenshot(_ name: String, failureEvidence: Bool = false) throws {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
    p.arguments = ["-x", out!.appendingPathComponent(name + ".png").path]
    try p.run()
    let captureEnd = failureEvidence ? Date().addingTimeInterval(10) : deadline
    while p.isRunning && Date() < captureEnd {
        RunLoop.current.run(until: Date().addingTimeInterval(0.1))
    }
    if p.isRunning { p.terminate(); p.waitUntilExit(); throw Refusal(message: "screenshot timeout") }
    try require(p.terminationStatus == 0, "screen capture refused")
    let url = out!.appendingPathComponent(name + ".png")
    guard let image = NSBitmapImageRep(data: try Data(contentsOf: url)) else { throw Refusal(message: "invalid screenshot pixels") }
    try require(image.pixelsWide == 1600 && image.pixelsHigh == 900, "screenshot is not unscaled 1600x900")
    record("screenshot", ["name": url.lastPathComponent, "width": image.pixelsWide, "height": image.pixelsHigh])
}
func inputState() -> [String: Any] {
    let combined = CGEventSource.buttonState(.combinedSessionState, button: .left)
    let hardware = CGEventSource.buttonState(.hidSystemState, button: .left)
    return ["combinedDown": combined, "hardwareDown": hardware, "neutral": !combined && !hardware,
            "api": "CGEventSource.buttonState", "deliveryAcknowledged": false]
}
func observeHelperBirth() throws -> String {
    if let birth = helperBirth { return birth }
    let child = Process(); let pipe = Pipe()
    child.executableURL = URL(fileURLWithPath: "/bin/ps")
    child.arguments = ["-p", String(getpid()), "-o", "lstart="]
    child.standardOutput = pipe; child.standardError = FileHandle.nullDevice
    try child.run()
    let end = min(deadline, Date().addingTimeInterval(2))
    while child.isRunning && Date() < end { RunLoop.current.run(until: Date().addingTimeInterval(0.01)) }
    if child.isRunning { child.terminate(); child.waitUntilExit(); throw Refusal(message: "helper birth probe deadline") }
    child.waitUntilExit()
    let birth = String(data: pipe.fileHandleForReading.readData(ofLength: 128), encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    record("helper-native-birth", ["pid": getpid(), "uid": getuid(), "birth": birth,
        "probePID": child.processIdentifier, "probeExit": child.terminationStatus])
    try require(child.terminationStatus == 0 && !birth.isEmpty, "helper native birth unknown")
    helperBirth = birth
    return birth
}
// One retained source/pair, no global release into an unknown recipient. A post
// call returning is NOT a delivery acknowledgement. Leaf diagnostics cannot
// prevent an independently qualified release of our outstanding owned Down.
func pointerPair(_ element: AXUIElement, _ point: CGPoint, _ label: String,
                 _ index: Int, _ fileItem: FileItemCustody?) throws -> Int {
    try require(pendingPairs.isEmpty && Date() < deadline, "pending input or original pointer deadline")
    try require(inputState()["neutral"] as? Bool == true, "preexisting button state is not neutral")
    try requireControlCustody(element)
    guard let window = panelAncestors(element).1 else { throw Refusal(message: "pair window unknown") }
    var recipient: pid_t = 0
    try require(AXUIElementGetPid(element, &recipient) == .success, "pair recipient unavailable")
    guard let actor = NSRunningApplication(processIdentifier: recipient), let birth = actor.launchDate,
          let executable = actor.executableURL, let bundle = actor.bundleURL,
          let source = CGEventSource(stateID: .combinedSessionState),
          let down = CGEvent(mouseEventSource: source, mouseType: .leftMouseDown, mouseCursorPosition: point, mouseButton: .left),
          let up = CGEvent(mouseEventSource: source, mouseType: .leftMouseUp, mouseCursorPosition: point, mouseButton: .left) else {
        throw Refusal(message: "native pair/actor construction unavailable")
    }
    let nativeBirth = try observeHelperBirth()
    pairSequence += 1; let id = pairSequence
    // Apple documents that matching Down/Up share mouseEventNumber. Retain
    // the number actually constructed for Down; no historical-cause inference.
    let number = down.getIntegerValueField(.mouseEventNumber)
    for event in [down, up] {
        event.setIntegerValueField(.mouseEventNumber, value: number)
        event.setIntegerValueField(.mouseEventClickState, value: Int64(index))
    }
    func pairRecord(_ kind: String, _ extra: [String: Any] = [:]) {
        var fields: [String: Any] = ["pairID": id, "label": label, "clickIndex": index,
            "helperPID": getpid(), "helperBirth": nativeBirth, "recipientPID": recipient,
            "recipientBirth": birth.timeIntervalSince1970, "executable": executable.path,
            "bundle": bundle.path, "x": point.x, "y": point.y, "eventNumber": number,
            "sourceState": source.sourceStateID.rawValue, "deadline": deadline.timeIntervalSince1970,
            "uptimeNs": DispatchTime.now().uptimeNanoseconds,
            "deliveryAcknowledged": false]
        fields.merge(extra) { _, new in new }; record(kind, fields)
    }
    func releaseCustody() throws {
        try require(Date() < deadline && pendingPairs.contains(id) && CGPreflightPostEventAccess(), "owned release deadline/input permission")
        guard let current = NSRunningApplication(processIdentifier: recipient) else { throw Refusal(message: "release actor absent") }
        try require(!current.isTerminated && current.launchDate == birth && current.executableURL == executable &&
                    current.bundleURL == bundle, "release PID/birth/executable changed")
        try requireControlCustody(window)
        let rootPID = owned?.processIdentifier ?? recipient
        let windows = value(AXUIElementCreateApplication(rootPID), kAXWindowsAttribute) as? [AXUIElement] ?? []
        try require(windows.contains { CFEqual($0, window) }, "original release window no longer owned")
        let cursor = CGEvent(source: nil)!.location
        try require(abs(cursor.x-point.x) < 3 && abs(cursor.y-point.y) < 3 &&
                    (try observedRect(window)).contains(point), "release point/cursor custody changed")
        var hit: AXUIElement?
        let status = AXUIElementCopyElementAtPosition(AXUIElementCreateSystemWide(), Float(point.x), Float(point.y), &hit)
        var hitPID: pid_t = 0
        if let hit = hit { AXUIElementGetPid(hit, &hitPID) }
        var within = false
        for _ in 0..<32 {
            guard let node = hit else { break }
            if CFEqual(node, window) { within = true; break }
            hit = axParent(node)
        }
        pairRecord("pointer-release-custody", ["hitStatus": status.rawValue, "hitPID": hitPID,
                    "exactHeldWindowAncestor": within])
        try require(status == .success && hitPID == recipient && within, "release window/point hit unproven")
    }
    var upAttempted = false
    func release() throws {
        try releaseCustody()
        try require(!upAttempted, "duplicate owned Up")
        upAttempted = true
        // Never throw on persistence before release. The original exact Up
        // still runs; stderr/final failure records persistence independently.
        pairRecord("pointer-up-attempt", ["eventNumber": up.getIntegerValueField(.mouseEventNumber),
            "clickIndex": up.getIntegerValueField(.mouseEventClickState), "nativeEventType": up.type.rawValue])
        up.post(tap: .cghidEventTap)
        pairRecord("pointer-up-return", ["state": inputState()])
        while inputState()["neutral"] as? Bool != true && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.001))
        }
        let state = inputState()
        pairRecord("pointer-pair-neutral", ["state": state])
        try require(state["neutral"] as? Bool == true, "owned Up posted but native neutral unproven")
        pendingPairs.remove(id)
    }
    pairRecord("pointer-pair-start", ["state": inputState(), "target": describeTarget(element),
                                      "window": describeTarget(window)])
    try require(!evidenceWriteFailed, "pair custody persistence failed before Down")
    do {
        try requireExactHit(element, point, label, fileItem: fileItem)
        let current = NSRunningApplication(processIdentifier: recipient)
        let cursor = CGEvent(source: nil)!.location
        try require(current?.launchDate == birth && current?.executableURL == executable &&
                    current?.bundleURL == bundle && current?.isTerminated == false &&
                    inputState()["neutral"] as? Bool == true && Date() < deadline &&
                    abs(cursor.x-point.x) < 3 && abs(cursor.y-point.y) < 3,
                    "original actor/point/input custody changed before Down")
    }
    catch {
        pairRecord("pointer-pair-not-posted", ["error": String(describing: error)])
        throw error
    }
    pendingPairs.insert(id)
    pairRecord("pointer-down-attempt", ["eventNumber": down.getIntegerValueField(.mouseEventNumber),
        "clickIndex": down.getIntegerValueField(.mouseEventClickState), "nativeEventType": down.type.rawValue])
    if evidenceWriteFailed {
        pendingPairs.remove(id)
        pairRecord("pointer-pair-not-posted", ["error": "Down not posted: durable attempt failed"])
        throw Refusal(message: "Down not posted: durable attempt failed")
    }
    do {
        down.post(tap: .cghidEventTap)
        pairRecord("pointer-down-return", ["state": inputState()])
        try require(!evidenceWriteFailed, "Down-return persistence failed")
        try requireControlCustody(element)
        try requireExactHit(element, point, label, fileItem: fileItem)
        try release()
        pairRecord("pointer-pair-end", ["succeeded": true])
        try require(!evidenceWriteFailed, "pair final persistence failed")
    } catch {
        let original = error
        pairRecord("pointer-pair-first-failure", ["error": String(describing: original)])
        if !upAttempted {
            do { try release() }
            catch { pairRecord("pointer-pair-secondary-failure", ["error": String(describing: error), "pending": pendingPairs.contains(id)]) }
        }
        pairRecord("pointer-pair-end", ["succeeded": false, "pending": pendingPairs.contains(id)])
        throw original
    }
    return id
}
func click(_ element: AXUIElement, _ label: String, double: Bool = false, fileItem: FileItemCustody? = nil) throws {
    try requireControlCustody(element)
    try require((value(element, kAXEnabledAttribute) as? Bool) == true, "disabled or unknown enabled state: " + label)
    try revealOwnedControl(element, label)
    let rect = try settledGeometry(element)
    let point = CGPoint(x: rect.midX, y: rect.midY)
    var pid: pid_t = 0
    AXUIElementGetPid(element, &pid)
    try requireExactHit(element, point, label, fileItem: fileItem)
    let before = CGEvent(source: nil)!.location
    CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: point,
            mouseButton: .left)!.post(tap: .cghidEventTap)
    try guiWaitTick()
    let after = CGEvent(source: nil)!.location
    try require(abs(after.x-point.x) < 3 && abs(after.y-point.y) < 3, "pointer motion not observed")
    try screenshot(label + "-hover")
    try require((value(element, kAXEnabledAttribute) as? Bool) == true, "enabled state changed after hover")
    try require(try bounds(element) == rect, "control moved after hover")
    try require(try actualControlViewport(element).viewport.contains(rect), "actual clipping changed after hover")
    try requireExactHit(element, point, label, fileItem: fileItem)
    var pairs: [Int] = []
    for n in 1...(double ? 2 : 1) {
        pairs.append(try pointerPair(element, point, label, n, fileItem))
    }
    record("pointer-click", ["label": label, "pid": pid, "x": point.x, "y": point.y,
                             "beforeX": before.x, "beforeY": before.y, "observedX": after.x, "observedY": after.y,
                             "pairIDs": pairs])
}

var failed = false
do {
    try require([3, 4].contains(CommandLine.arguments.count) || chooserDiagnostic, "app/output and optional exact Documents image paths required")
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
    try prepareActualDisplay()
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
            record("gui-pre-build-checkpoint", ["pid": app.processIdentifier, "BuildInvoked": false])
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
    guard let mainWindow = windows.first(where: { text($0, kAXTitleAttribute) == "SteamOS NVIDIA Builder" }) else {
        throw Refusal(message: "actual main window unavailable for usable-layout observation")
    }
    let mainFrame = try observedRect(mainWindow)
    let usableFrame = try usableDisplayBounds()
    record("native-usable-window-observed", ["display": NSStringFromRect(CGDisplayBounds(CGMainDisplayID())),
        "usableBounds": NSStringFromRect(usableFrame), "windowBounds": NSStringFromRect(mainFrame),
        "pid": owned!.processIdentifier])
    try require(usableFrame.contains(mainFrame), "actual main window exceeds native usable work area")
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
    // Both modes use the real chooser. Full-stack mode below consumes only the
    // exact admitted image and requires the actual Build/guest transition.
    func chooserCancel() throws -> AXUIElement? {
        let windows = value(root, kAXWindowsAttribute) as? [AXUIElement] ?? []
        var candidates: [AXUIElement] = []
        for window in windows {
            if let cancel = try find(window, unique: true, validateCustody: false, { element in
                text(element, kAXRoleAttribute) == "AXButton" &&
                    [text(element, kAXTitleAttribute), text(element, kAXDescriptionAttribute)].contains("Cancel")
            }) {
                try bindChooser(cancel, window: window)
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
    chooserRequestedAt = Date()
    try click(choose!, "choose-image")
    var cancel: AXUIElement?
    while cancel == nil { cancel = try chooserCancel(); if cancel == nil { try guiWaitTick() } }
    try screenshot("native-image-chooser-open")
    record("native-image-chooser-observed", ["appPID": owned!.processIdentifier])
    if chooserDiagnostic {
        _ = try find(root) { element in
            let role = text(element, kAXRoleAttribute)
            if ["AXRow", "AXCell", "AXImage", "AXStaticText", "AXTextField", "AXColumn", "AXBrowser"].contains(role) {
                var fields: [String: Any] = ["role": role]
                for attribute in [kAXTitleAttribute, kAXDescriptionAttribute, kAXValueAttribute, kAXURLAttribute, "AXFilename"] {
                    if let observed = value(element, attribute) {
                        fields[attribute] = String(describing: observed).prefix(512).description
                        fields[attribute + "TypeID"] = CFGetTypeID(observed)
                    }
                }
                record("chooser-native-node", fields)
            }
            return false
        }
        try click(cancel!, "cancel-diagnostic-chooser")
        while try chooserCancel() != nil { try guiWaitTick() }
        record("chooser-diagnostic-only", ["BuildInvoked": false, "acceptance": false])
    } else if let image = fullStackImage {
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
                let resolved = nativeFilePath(file)
                let matches = ["AXCell", "AXRow", "AXImage", "AXTextField"].contains(text(element, kAXRoleAttribute)) && resolved == image
                if matches {
                    record("chooser-exact-file-identity", ["observedURL": file?.absoluteString ?? "",
                        "resolvedPath": resolved?.path ?? "", "expectedPath": image.path,
                        "role": text(element, kAXRoleAttribute)])
                }
                return matches
            }
            if fileCell == nil { try guiWaitTick() }
        }
        guard let fileCell = fileCell else { throw Refusal(message: "exact admitted file URL not visibly selectable in native chooser") }
        let fileItem = try qualifyFileItem(fileCell, image)
        try click(fileCell, "choose-pinned-image", double: true, fileItem: fileItem)
        while try chooserCancel() != nil { try guiWaitTick() }
        record("native-image-selected-observed", ["path": image.path])
        try screenshot("pinned-image-selected")
        var build: AXUIElement?
        while build == nil {
            if let candidate = try button("Build NVIDIA Image"),
               (value(candidate, kAXEnabledAttribute) as? Bool) == true { build = candidate }
            else { try guiWaitTick() }
        }
        record("build-request-intent", ["pid": owned!.processIdentifier])
        try click(build!, "build-pinned-image")
        var observedHashing = false
        var observedReady = false
        var observedHealth = false
        var observedNext = false
        var observedComplete = false
        var completionText = ""
        var nextCapture = Date.distantPast
        while !observedComplete {
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
            observedNext = observedNext || visible.contains("Selected image:")
            observedComplete = visible.contains("NVIDIA image ready for USB Imaging") && visible.contains("Build manifest:") && visible.contains("Export validation:")
            if observedComplete { completionText = visible }
            if Date() >= nextCapture {
                record("visible-build-state", ["text": String(visible.prefix(32768)),
                    "tail": String(visible.suffix(32768)), "originalCharacters": visible.count,
                    "hashing": observedHashing, "ready": observedReady, "health": observedHealth, "nextStage": observedNext])
                try screenshot("build-" + String(events.count))
                nextCapture = Date().addingTimeInterval(10)
            }
            if visible.contains("Build failed") || visible.contains("timed out") || visible.contains("timedOut") {
                throw Refusal(message: "actual Build failure; retained visible text and screenshot")
            }
            if !observedComplete { try guiWaitTick() }
        }
        try require(observedHashing && observedReady && observedHealth,
                    "next stage lacks observed hashing, cold readiness or guest health")
        record("cold-build-next-stage-observed", ["outputAcceptance": false])
        try require(observedNext, "completed build lacks observed selected-image stage")
        record("completed-image-ui-observed", ["text": completionText, "independentFullHashPending": true])
        var closeProgress: AXUIElement?
        while closeProgress == nil { closeProgress = try button("Close"); if closeProgress == nil { try guiWaitTick() } }
        try screenshot("completed-build")
        try click(closeProgress!, "close-build-progress")
        // A distinct second transaction exercises cancellation. It cannot stand
        // in for the completed first image, whose manifest/full hash is checked
        // independently by the outer same-job consumer.
        var repeatBuild: AXUIElement?
        while repeatBuild == nil {
            if let candidate = try button("Build NVIDIA Image"),
               (value(candidate, kAXEnabledAttribute) as? Bool) == true { repeatBuild = candidate }
            else { try guiWaitTick() }
        }
        try click(repeatBuild!, "build-for-separate-cancel")
        var cancelBuild: AXUIElement?
        while cancelBuild == nil { cancelBuild = try button("Cancel Build"); if cancelBuild == nil { try guiWaitTick() } }
        try click(cancelBuild!, "cancel-separate-build")
        var closeCancelled: AXUIElement?
        while closeCancelled == nil { closeCancelled = try button("Close"); if closeCancelled == nil { try guiWaitTick() } }
        record("separate-build-cancel-observed", ["completedImageAcceptance": false])
        try screenshot("separate-cancelled-build")
        try click(closeCancelled!, "close-separate-cancel")
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
    if out != nil && CGPreflightScreenCaptureAccess() { try? screenshot("failure-desktop", failureEvidence: true) }
}
if let app = owned {
    record("owned-app-final-state", ["pid": app.processIdentifier, "terminated": app.isTerminated,
                                     "numericExit": "unknown"])
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
let finalInput = inputState()
record("pointer-input-final", ["state": finalInput, "pendingPairIDs": pendingPairs.sorted(),
                               "evidenceWriteFailed": evidenceWriteFailed, "helperPID": getpid(),
                               "helperBirth": helperBirth ?? "not-observed", "uptimeNs": DispatchTime.now().uptimeNanoseconds])
if !pendingPairs.isEmpty || finalInput["neutral"] as? Bool != true || evidenceWriteFailed { failed = true }
exit(failed ? 1 : 0)
