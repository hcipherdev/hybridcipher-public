import Foundation

enum ProviderEntryKind: String, Codable {
    case directory
    case file
}

enum ProviderChangeKind: String, Codable {
    case upsert
    case delete
}

struct FileIdentityV1: Codable, Hashable {
    let version: UInt16
    let rootId: UUID
    let kind: ProviderEntryKind
    let relativePath: String
    let pathHashHex: String
    let fileId: String?
    let epochId: UInt64?

    enum CodingKeys: String, CodingKey {
        case version
        case rootId = "root_id"
        case kind
        case relativePath = "relative_path"
        case pathHashHex = "path_hash_hex"
        case fileId = "file_id"
        case epochId = "epoch_id"
    }
}

struct ProviderItemSnapshot: Codable, Hashable {
    let rootId: UUID
    let providerId: String
    let parentProviderId: String?
    let relativePath: String
    let kind: ProviderEntryKind
    let logicalSize: UInt64
    let encryptedSize: UInt64
    let modifiedAt: Date
    let contentVersion: Data
    let metadataVersion: Data
    let identity: FileIdentityV1

    enum CodingKeys: String, CodingKey {
        case rootId = "root_id"
        case providerId = "provider_id"
        case parentProviderId = "parent_provider_id"
        case relativePath = "relative_path"
        case kind
        case logicalSize = "logical_size"
        case encryptedSize = "encrypted_size"
        case modifiedAt = "modified_at"
        case contentVersion = "content_version"
        case metadataVersion = "metadata_version"
        case identity
    }

    init(
        rootId: UUID,
        providerId: String,
        parentProviderId: String?,
        relativePath: String,
        kind: ProviderEntryKind,
        logicalSize: UInt64,
        encryptedSize: UInt64,
        modifiedAt: Date,
        contentVersion: Data,
        metadataVersion: Data,
        identity: FileIdentityV1
    ) {
        self.rootId = rootId
        self.providerId = providerId
        self.parentProviderId = parentProviderId
        self.relativePath = relativePath
        self.kind = kind
        self.logicalSize = logicalSize
        self.encryptedSize = encryptedSize
        self.modifiedAt = modifiedAt
        self.contentVersion = contentVersion
        self.metadataVersion = metadataVersion
        self.identity = identity
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        rootId = try container.decode(UUID.self, forKey: .rootId)
        providerId = try container.decode(String.self, forKey: .providerId)
        parentProviderId = try container.decodeIfPresent(String.self, forKey: .parentProviderId)
        relativePath = try container.decode(String.self, forKey: .relativePath)
        kind = try container.decode(ProviderEntryKind.self, forKey: .kind)
        logicalSize = try container.decode(UInt64.self, forKey: .logicalSize)
        encryptedSize = try container.decode(UInt64.self, forKey: .encryptedSize)
        modifiedAt = try container.decode(Date.self, forKey: .modifiedAt)
        contentVersion = try Self.decodeVersionData(from: container, forKey: .contentVersion)
        metadataVersion = try Self.decodeVersionData(from: container, forKey: .metadataVersion)
        identity = try container.decode(FileIdentityV1.self, forKey: .identity)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rootId, forKey: .rootId)
        try container.encode(providerId, forKey: .providerId)
        try container.encodeIfPresent(parentProviderId, forKey: .parentProviderId)
        try container.encode(relativePath, forKey: .relativePath)
        try container.encode(kind, forKey: .kind)
        try container.encode(logicalSize, forKey: .logicalSize)
        try container.encode(encryptedSize, forKey: .encryptedSize)
        try container.encode(modifiedAt, forKey: .modifiedAt)
        try container.encode(Array(contentVersion), forKey: .contentVersion)
        try container.encode(Array(metadataVersion), forKey: .metadataVersion)
        try container.encode(identity, forKey: .identity)
    }

    private static func decodeVersionData(
        from container: KeyedDecodingContainer<CodingKeys>,
        forKey key: CodingKeys
    ) throws -> Data {
        do {
            return try container.decode(Data.self, forKey: key)
        } catch {
            return Data(try container.decode([UInt8].self, forKey: key))
        }
    }
}

struct ProviderChangeRecord: Codable, Hashable {
    let anchor: UInt64
    let kind: ProviderChangeKind
    let providerId: String
    let parentProviderId: String?
    let relativePath: String
    let snapshot: ProviderItemSnapshot?

    enum CodingKeys: String, CodingKey {
        case anchor
        case kind
        case providerId = "provider_id"
        case parentProviderId = "parent_provider_id"
        case relativePath = "relative_path"
        case snapshot
    }
}

struct ProviderChangeBatch: Hashable {
    let latestSyncAnchor: UInt64
    let syncAnchorExpired: Bool
    let records: [ProviderChangeRecord]
}

struct MacFileProviderStatus: Codable {
    let backend: String
    let available: Bool
    let extensionReady: Bool
    let runningRootCount: Int
    let message: String?

    enum CodingKeys: String, CodingKey {
        case backend
        case available
        case extensionReady = "extension_ready"
        case runningRootCount = "running_root_count"
        case message
    }
}

struct MountSyncRuntimeStatus: Codable {
    let safeToUnmount: Bool
    let pendingWritebackCount: Int
    let pendingConflictCount: Int
    let recoveredPendingCopyCount: Int
    let lastError: String?

    enum CodingKeys: String, CodingKey {
        case safeToUnmount = "safe_to_unmount"
        case pendingWritebackCount = "pending_writeback_count"
        case pendingConflictCount = "pending_conflict_count"
        case recoveredPendingCopyCount = "recovered_pending_copy_count"
        case lastError = "last_error"
    }
}

enum ProviderSocketRequest: Encodable {
    case status
    case startRoot(rootId: UUID)
    case stopRoot(rootId: UUID)
    case currentSyncAnchor(rootId: UUID)
    case changes(rootId: UUID, sinceAnchor: UInt64)
    case listDirectory(rootId: UUID, containerId: String?)
    case item(rootId: UUID, identifier: String)
    case hydrate(rootId: UUID, identifier: String, outputPath: String)
    case createDirectory(rootId: UUID, relativePath: String)
    case writeback(rootId: UUID, identifier: String, relativePath: String, contentsPath: String)
    case delete(rootId: UUID, identifier: String)
    case rename(rootId: UUID, identifier: String, targetRelativePath: String, contentsPath: String?)
    case listConflicts(rootId: UUID)
    case resolveConflict(rootId: UUID, request: Data)
    case listRecovery(rootId: UUID)
    case resolveRecovery(rootId: UUID, request: Data)
    case signalEnumerator(rootId: UUID)

    enum CodingKeys: String, CodingKey {
        case command
        case rootId = "root_id"
        case sinceAnchor = "since_anchor"
        case containerId = "container_id"
        case identifier
        case outputPath = "output_path"
        case relativePath = "relative_path"
        case contentsPath = "plaintext_path"
        case targetPlaintextPath = "target_plaintext_path"
        case targetRelativePath = "target_relative_path"
        case request
    }

    enum Command: String, Codable {
        case status
        case startRoot = "start-root"
        case stopRoot = "stop-root"
        case currentSyncAnchor = "current-sync-anchor"
        case changes
        case listDirectory = "list-directory"
        case item
        case hydrate
        case createDirectory = "create-directory"
        case writeback
        case delete
        case rename
        case listConflicts = "list-conflicts"
        case resolveConflict = "resolve-conflict"
        case listRecovery = "list-recovery"
        case resolveRecovery = "resolve-recovery"
        case signalEnumerator = "signal-enumerator"
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .status:
            try container.encode(Command.status, forKey: .command)
        case .startRoot(let rootId):
            try container.encode(Command.startRoot, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
        case .stopRoot(let rootId):
            try container.encode(Command.stopRoot, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
        case .currentSyncAnchor(let rootId):
            try container.encode(Command.currentSyncAnchor, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
        case .changes(let rootId, let sinceAnchor):
            try container.encode(Command.changes, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
            try container.encode(sinceAnchor, forKey: .sinceAnchor)
        case .listDirectory(let rootId, let containerId):
            try container.encode(Command.listDirectory, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
            try container.encodeIfPresent(containerId, forKey: .containerId)
        case .item(let rootId, let identifier):
            try container.encode(Command.item, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
            try container.encode(identifier, forKey: .identifier)
        case .hydrate(let rootId, let identifier, let outputPath):
            try container.encode(Command.hydrate, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
            try container.encode(identifier, forKey: .identifier)
            try container.encode(outputPath, forKey: .outputPath)
        case .createDirectory(let rootId, let relativePath):
            try container.encode(Command.createDirectory, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
            try container.encode(relativePath, forKey: .relativePath)
        case .writeback(let rootId, let identifier, let relativePath, let contentsPath):
            try container.encode(Command.writeback, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
            try container.encode(identifier, forKey: .identifier)
            try container.encode(relativePath, forKey: .relativePath)
            try container.encode(contentsPath, forKey: .contentsPath)
        case .delete(let rootId, let identifier):
            try container.encode(Command.delete, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
            try container.encode(identifier, forKey: .identifier)
        case .rename(let rootId, let identifier, let targetRelativePath, let contentsPath):
            try container.encode(Command.rename, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
            try container.encode(identifier, forKey: .identifier)
            try container.encode(targetRelativePath, forKey: .targetRelativePath)
            try container.encodeIfPresent(contentsPath, forKey: .targetPlaintextPath)
        case .listConflicts(let rootId):
            try container.encode(Command.listConflicts, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
        case .resolveConflict(let rootId, let request):
            try container.encode(Command.resolveConflict, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
            try container.encode(request, forKey: .request)
        case .listRecovery(let rootId):
            try container.encode(Command.listRecovery, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
        case .resolveRecovery(let rootId, let request):
            try container.encode(Command.resolveRecovery, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
            try container.encode(request, forKey: .request)
        case .signalEnumerator(let rootId):
            try container.encode(Command.signalEnumerator, forKey: .command)
            try container.encode(rootId, forKey: .rootId)
        }
    }
}

struct ProviderSocketResponse: Codable {
    let ok: Bool
    let status: MacFileProviderStatus?
    let runtimeStatus: MountSyncRuntimeStatus?
    let snapshots: [ProviderItemSnapshot]?
    let snapshot: ProviderItemSnapshot?
    let changes: [ProviderChangeRecord]?
    let latestSyncAnchor: UInt64?
    let syncAnchorExpired: Bool?
    let message: String?

    enum CodingKeys: String, CodingKey {
        case ok
        case status
        case runtimeStatus = "runtime_status"
        case snapshots
        case snapshot
        case changes
        case latestSyncAnchor = "latest_sync_anchor"
        case syncAnchorExpired = "sync_anchor_expired"
        case message
    }
}
