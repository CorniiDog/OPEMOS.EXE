#!/usr/bin/env swift

import AppKit
import Foundation

guard CommandLine.arguments.count == 3 else {
    FileHandle.standardError.write(Data("usage: render_macos_icon.swift SOURCE.svg OUTPUT.png\n".utf8))
    exit(64)
}

let source = CommandLine.arguments[1]
let destination = CommandLine.arguments[2]
let pixels = 1024

guard let image = NSImage(contentsOfFile: source) else {
    FileHandle.standardError.write(Data("could not decode SVG source: \(source)\n".utf8))
    exit(1)
}
guard let bitmap = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: pixels,
    pixelsHigh: pixels,
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bitmapFormat: [],
    bytesPerRow: pixels * 4,
    bitsPerPixel: 32
) else {
    FileHandle.standardError.write(Data("could not allocate transparent icon bitmap\n".utf8))
    exit(1)
}

bitmap.size = NSSize(width: pixels, height: pixels)
guard let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
    FileHandle.standardError.write(Data("could not create icon graphics context\n".utf8))
    exit(1)
}

NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context
context.cgContext.clear(CGRect(x: 0, y: 0, width: pixels, height: pixels))
image.draw(
    in: NSRect(x: 0, y: 0, width: pixels, height: pixels),
    from: .zero,
    operation: .sourceOver,
    fraction: 1,
    respectFlipped: false,
    hints: [.interpolation: NSImageInterpolation.high]
)
context.flushGraphics()
NSGraphicsContext.restoreGraphicsState()

func requireTransparent(x: Int, y: Int) {
    guard bitmap.colorAt(x: x, y: y)?.alphaComponent == 0 else {
        FileHandle.standardError.write(Data("rendered icon has pixels outside its contour at (\(x), \(y))\n".utf8))
        exit(1)
    }
}

let transparentMargin = 32
for offset in 0..<transparentMargin {
    for coordinate in 0..<pixels {
        requireTransparent(x: coordinate, y: offset)
        requireTransparent(x: coordinate, y: pixels - 1 - offset)
        requireTransparent(x: offset, y: coordinate)
        requireTransparent(x: pixels - 1 - offset, y: coordinate)
    }
}

guard let png = bitmap.representation(using: .png, properties: [:]) else {
    FileHandle.standardError.write(Data("could not encode rendered icon as PNG\n".utf8))
    exit(1)
}
try png.write(to: URL(fileURLWithPath: destination), options: .atomic)
