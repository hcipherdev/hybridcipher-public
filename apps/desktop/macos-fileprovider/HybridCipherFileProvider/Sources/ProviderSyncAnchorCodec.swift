import FileProvider
import Foundation

enum ProviderSyncAnchorCodec {
    static func encode(_ anchor: UInt64) -> NSFileProviderSyncAnchor {
        var bigEndian = anchor.bigEndian
        let data = withUnsafeBytes(of: &bigEndian) { Data($0) }
        return NSFileProviderSyncAnchor(rawValue: data)
    }

    static func decode(_ anchor: NSFileProviderSyncAnchor) -> UInt64 {
        let rawValue = anchor.rawValue
        guard rawValue.count == MemoryLayout<UInt64>.size else {
            return 0
        }
        return rawValue.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else {
                return 0
            }
            return baseAddress.assumingMemoryBound(to: UInt64.self).pointee.bigEndian
        }
    }
}
