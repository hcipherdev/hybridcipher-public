import Darwin
import Foundation

protocol ProviderEnumeratorBridge {
    func currentSyncAnchor() async throws -> UInt64
    func changes(sinceAnchor: UInt64) async throws -> ProviderChangeBatch
    func listDirectory(containerIdentifier: String?) async throws -> [ProviderItemSnapshot]
}

enum ProviderBridgeError: Error, LocalizedError {
    case appGroupUnavailable(String)
    case socketPathTooLong(String)
    case connectFailed(String)
    case writeFailed(String)
    case readFailed(String)
    case providerRejected(String)

    var errorDescription: String? {
        switch self {
        case .appGroupUnavailable(let group):
            return "App group container is unavailable: \(group)"
        case .socketPathTooLong(let path):
            return "Provider socket path is too long: \(path)"
        case .connectFailed(let detail):
            return "Provider socket connect failed: \(detail)"
        case .writeFailed(let detail):
            return "Provider socket write failed: \(detail)"
        case .readFailed(let detail):
            return "Provider socket read failed: \(detail)"
        case .providerRejected(let detail):
            return detail
        }
    }
}

actor ProviderBridgeClient: ProviderEnumeratorBridge {
    static let unixSocketPathLimit = 104

    private let rootId: UUID
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder
    private let socketURL: URL

    init(rootId: UUID, socketURL: URL? = nil) throws {
        self.rootId = rootId
        self.socketURL = socketURL ?? Self.defaultSocketURL(rootId: rootId)
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        self.decoder.dateDecodingStrategy = .iso8601
        self.encoder.dateEncodingStrategy = .iso8601
    }

    private static func defaultSocketURL(rootId: UUID) -> URL {
        let rootHex = rootId.uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let shortRoot = String(rootHex.prefix(16))
        let filename = "\(shortRoot).sock"
        let groupIdentifier = ProviderAppGroup.identifier()
        if let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupIdentifier) {
            let candidate = container
                .appendingPathComponent("s", isDirectory: true)
                .appendingPathComponent(filename)
            if candidate.path.utf8.count < unixSocketPathLimit {
                return candidate
            }
        }

        return URL(fileURLWithPath: "/tmp", isDirectory: true)
            .appendingPathComponent("hc-fp", isDirectory: true)
            .appendingPathComponent(filename)
    }

    func status() async throws -> ProviderSocketResponse {
        try await request(.status)
    }

    func currentSyncAnchor() async throws -> UInt64 {
        let response = try await request(.currentSyncAnchor(rootId: rootId))
        return response.latestSyncAnchor ?? 0
    }

    func changes(sinceAnchor: UInt64) async throws -> ProviderChangeBatch {
        let response = try await request(.changes(rootId: rootId, sinceAnchor: sinceAnchor))
        return ProviderChangeBatch(
            latestSyncAnchor: response.latestSyncAnchor ?? sinceAnchor,
            syncAnchorExpired: response.syncAnchorExpired ?? false,
            records: response.changes ?? []
        )
    }

    func listDirectory(containerIdentifier: String?) async throws -> [ProviderItemSnapshot] {
        let response = try await request(.listDirectory(rootId: rootId, containerId: containerIdentifier))
        return response.snapshots ?? []
    }

    func item(identifier: String) async throws -> ProviderItemSnapshot? {
        let response = try await request(.item(rootId: rootId, identifier: identifier))
        return response.snapshot
    }

    func hydrate(identifier: String, outputURL: URL) async throws -> ProviderItemSnapshot? {
        let response = try await request(.hydrate(
            rootId: rootId,
            identifier: identifier,
            outputPath: outputURL.path
        ))
        return response.snapshot
    }

    func createDirectory(relativePath: String) async throws -> ProviderItemSnapshot? {
        let response = try await request(.createDirectory(
            rootId: rootId,
            relativePath: relativePath
        ))
        return response.snapshot
    }

    func writeback(identifier: String, relativePath: String, contentsURL: URL) async throws -> ProviderItemSnapshot? {
        let response = try await request(.writeback(
            rootId: rootId,
            identifier: identifier,
            relativePath: relativePath,
            contentsPath: contentsURL.path
        ))
        return response.snapshot
    }

    func delete(identifier: String) async throws {
        _ = try await request(.delete(rootId: rootId, identifier: identifier))
    }

    func rename(identifier: String, targetRelativePath: String, contentsURL: URL?) async throws -> ProviderItemSnapshot? {
        let response = try await request(.rename(
            rootId: rootId,
            identifier: identifier,
            targetRelativePath: targetRelativePath,
            contentsPath: contentsURL?.path
        ))
        return response.snapshot
    }

    func signalEnumerator() async throws {
        _ = try await request(.signalEnumerator(rootId: rootId))
    }

    private func request(_ request: ProviderSocketRequest) async throws -> ProviderSocketResponse {
        let requestData = try encoder.encode(request)
        let fd = try connectSocket()
        defer { close(fd) }
        try writeAll(requestData + Data([0x0a]), to: fd)
        shutdown(fd, SHUT_WR)
        let responseData = try readAll(from: fd)
        let response = try decoder.decode(ProviderSocketResponse.self, from: responseData)
        guard response.ok else {
            throw ProviderBridgeError.providerRejected(response.message ?? "Provider operation failed")
        }
        return response
    }

    private func connectSocket() throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw ProviderBridgeError.connectFailed(String(cString: strerror(errno)))
        }

        // Set send/receive timeouts to prevent the extension from hanging
        // indefinitely if the host process is blocked or unresponsive.
        var timeout = timeval(tv_sec: 30, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        var pathBytes = Array(socketURL.path.utf8)
        pathBytes.append(0)
        let maxPathLength = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count <= maxPathLength else {
            close(fd)
            throw ProviderBridgeError.socketPathTooLong(socketURL.path)
        }

        withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: UInt8.self, capacity: maxPathLength) { buffer in
                for index in 0..<pathBytes.count {
                    buffer[index] = pathBytes[index]
                }
            }
        }

        let addressLength = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, addressLength)
            }
        }
        guard result == 0 else {
            let detail = String(cString: strerror(errno))
            close(fd)
            throw ProviderBridgeError.connectFailed(detail)
        }
        return fd
    }

    private func writeAll(_ data: Data, to fd: Int32) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < data.count {
                let written = Darwin.write(fd, base.advanced(by: offset), data.count - offset)
                guard written > 0 else {
                    throw ProviderBridgeError.writeFailed(String(cString: strerror(errno)))
                }
                offset += written
            }
        }
    }

    private func readAll(from fd: Int32) throws -> Data {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let readCount = Darwin.read(fd, &buffer, buffer.count)
            if readCount == 0 {
                return data
            }
            guard readCount > 0 else {
                throw ProviderBridgeError.readFailed(String(cString: strerror(errno)))
            }
            data.append(buffer, count: readCount)
        }
    }
}
