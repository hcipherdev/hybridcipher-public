import FileProvider
import Foundation

func require(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        exit(1)
    }
}

func awaitValue<T>(_ operation: @escaping () async -> T) -> T {
    let semaphore = DispatchSemaphore(value: 0)
    var result: T!
    Task {
        result = await operation()
        semaphore.signal()
    }
    semaphore.wait()
    return result
}

actor FakeEnumeratorBridge: ProviderEnumeratorBridge {
    private(set) var listedContainerIdentifiers: [String?] = []
    private(set) var requestedAnchors: [UInt64] = []
    private let listDirectoryResult: [ProviderItemSnapshot]
    private let listDirectoryError: Error?
    private let changeBatch: ProviderChangeBatch
    private let currentAnchor: UInt64

    init(
        listDirectoryResult: [ProviderItemSnapshot] = [],
        listDirectoryError: Error? = nil,
        changeBatch: ProviderChangeBatch = ProviderChangeBatch(
            latestSyncAnchor: 0,
            syncAnchorExpired: false,
            records: []
        ),
        currentAnchor: UInt64 = 0
    ) {
        self.listDirectoryResult = listDirectoryResult
        self.listDirectoryError = listDirectoryError
        self.changeBatch = changeBatch
        self.currentAnchor = currentAnchor
    }

    func currentSyncAnchor() async throws -> UInt64 {
        currentAnchor
    }

    func changes(sinceAnchor: UInt64) async throws -> ProviderChangeBatch {
        requestedAnchors.append(sinceAnchor)
        return changeBatch
    }

    func listDirectory(containerIdentifier: String?) async throws -> [ProviderItemSnapshot] {
        listedContainerIdentifiers.append(containerIdentifier)
        if let listDirectoryError {
            throw listDirectoryError
        }
        return listDirectoryResult
    }
}

final class TestEnumerationObserver: NSObject, NSFileProviderEnumerationObserver {
    let finished = DispatchSemaphore(value: 0)
    var items: [NSFileProviderItem] = []
    var error: Error?

    func didEnumerate(_ updatedItems: [NSFileProviderItem]) {
        items.append(contentsOf: updatedItems)
    }

    func finishEnumerating(upTo nextPage: NSFileProviderPage?) {
        finished.signal()
    }

    func finishEnumeratingWithError(_ error: Error) {
        self.error = error
        finished.signal()
    }
}

final class TestChangeObserver: NSObject, NSFileProviderChangeObserver {
    let finished = DispatchSemaphore(value: 0)
    var updatedItems: [NSFileProviderItem] = []
    var deletedIdentifiers: [NSFileProviderItemIdentifier] = []
    var finishedAnchor: NSFileProviderSyncAnchor?
    var error: Error?

    func didUpdate(_ updatedItems: [NSFileProviderItem]) {
        self.updatedItems.append(contentsOf: updatedItems)
    }

    func didDeleteItems(withIdentifiers deletedItemIdentifiers: [NSFileProviderItemIdentifier]) {
        deletedIdentifiers.append(contentsOf: deletedItemIdentifiers)
    }

    func finishEnumeratingChanges(upTo anchor: NSFileProviderSyncAnchor, moreComing: Bool) {
        finishedAnchor = anchor
        finished.signal()
    }

    func finishEnumeratingWithError(_ error: Error) {
        self.error = error
        finished.signal()
    }
}

@main
struct ProviderFileProviderP1TestRunner {
    static func main() throws {
        testSnapshotDecodesVersionBytesFromJsonArrays()
        testSyncAnchorCodecRoundTripsBigEndianAnchor()
        testListDirectoryRequestUsesScopedContainerProtocol()
        testFileProviderItemUsesSnapshotIdentifiersAndVersions()
        testEnumeratorUsesDirectoryScopedListing()
        testTrashEnumeratorSkipsBridgeListing()
        testEnumeratorMapsChangesAndAdvancesSyncAnchor()
        testEnumeratorMapsBridgeConnectionFailureToFileProviderError()
    }

    static func testSnapshotDecodesVersionBytesFromJsonArrays() {
        let payload = Data(
            """
            {
              "root_id": "00741C18-F05F-45F2-8F54-4C1C84A7BC14",
              "provider_id": "hc:v2:file:file-123",
              "parent_provider_id": "hc:v2:dir:parent-456",
              "relative_path": "Docs/report.txt",
              "kind": "file",
              "logical_size": 42,
              "encrypted_size": 128,
              "modified_at": "2026-06-12T21:13:30Z",
              "content_version": [170, 187],
              "metadata_version": [204, 221],
              "identity": {
                "version": 1,
                "root_id": "00741C18-F05F-45F2-8F54-4C1C84A7BC14",
                "kind": "file",
                "relative_path": "Docs/report.txt",
                "path_hash_hex": "hash",
                "file_id": "file-123",
                "epoch_id": 7
              }
            }
            """.utf8
        )
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let snapshot = try! decoder.decode(ProviderItemSnapshot.self, from: payload)

        require(snapshot.contentVersion == Data([0xAA, 0xBB]), "snapshot should decode content_version byte arrays")
        require(snapshot.metadataVersion == Data([0xCC, 0xDD]), "snapshot should decode metadata_version byte arrays")
    }

    static func testSyncAnchorCodecRoundTripsBigEndianAnchor() {
        let encoded = ProviderSyncAnchorCodec.encode(0x0102_0304_0506_0708)
        require(encoded.rawValue.count == 8, "sync anchor encoding should use eight bytes")
        require(Array(encoded.rawValue) == [1, 2, 3, 4, 5, 6, 7, 8], "sync anchor bytes should be big-endian")
        require(
            ProviderSyncAnchorCodec.decode(encoded) == 0x0102_0304_0506_0708,
            "sync anchor should decode back to the original value"
        )
        require(
            ProviderSyncAnchorCodec.decode(NSFileProviderSyncAnchor(rawValue: Data())) == 0,
            "empty sync anchor should decode to zero"
        )
    }

    static func testListDirectoryRequestUsesScopedContainerProtocol() {
        let encoder = JSONEncoder()
        let request = ProviderSocketRequest.listDirectory(
            rootId: UUID(uuidString: "00741C18-F05F-45F2-8F54-4C1C84A7BC14")!,
            containerId: "hc:v2:dir:projects"
        )
        let payload = try! encoder.encode(request)
        let object = try! JSONSerialization.jsonObject(with: payload) as! [String: Any]
        require(object["command"] as? String == "list-directory", "request should encode the list-directory command")
        require(object["container_id"] as? String == "hc:v2:dir:projects", "request should encode the scoped container identifier")
    }

    static func testFileProviderItemUsesSnapshotIdentifiersAndVersions() {
        let snapshot = ProviderItemSnapshot(
            rootId: UUID(uuidString: "00741C18-F05F-45F2-8F54-4C1C84A7BC14")!,
            providerId: "hc:v2:file:file-123",
            parentProviderId: "hc:v2:dir:parent-456",
            relativePath: "Docs/report.txt",
            kind: .file,
            logicalSize: 42,
            encryptedSize: 128,
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
            contentVersion: Data([0xAA, 0xBB]),
            metadataVersion: Data([0xCC, 0xDD]),
            identity: FileIdentityV1(
                version: 1,
                rootId: UUID(uuidString: "00741C18-F05F-45F2-8F54-4C1C84A7BC14")!,
                kind: .file,
                relativePath: "Docs/report.txt",
                pathHashHex: "hash",
                fileId: "file-123",
                epochId: 7
            )
        )

        let item = FileProviderItem(snapshot: snapshot)

        require(item.itemIdentifier.rawValue == "hc:v2:file:file-123", "item identifier should use the opaque provider identifier")
        require(item.parentItemIdentifier.rawValue == "hc:v2:dir:parent-456", "parent identifier should use the provider snapshot parent identifier")
        require(item.filename == "report.txt", "filename should be derived from the relative path")
        require(item.itemVersion.contentVersion == Data([0xAA, 0xBB]), "content version should come from the snapshot content version")
        require(item.itemVersion.metadataVersion == Data([0xCC, 0xDD]), "metadata version should come from the snapshot metadata version")
    }

    static func testEnumeratorUsesDirectoryScopedListing() {
        let snapshot = ProviderItemSnapshot(
            rootId: UUID(uuidString: "00741C18-F05F-45F2-8F54-4C1C84A7BC14")!,
            providerId: "hc:v2:dir:projects",
            parentProviderId: nil,
            relativePath: "Projects",
            kind: .directory,
            logicalSize: 0,
            encryptedSize: 0,
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_100),
            contentVersion: Data([0x01]),
            metadataVersion: Data([0x02]),
            identity: FileIdentityV1(
                version: 1,
                rootId: UUID(uuidString: "00741C18-F05F-45F2-8F54-4C1C84A7BC14")!,
                kind: .directory,
                relativePath: "Projects",
                pathHashHex: "dirhash",
                fileId: nil,
                epochId: nil
            )
        )
        let bridge = FakeEnumeratorBridge(listDirectoryResult: [snapshot])
        let observer = TestEnumerationObserver()
        let enumerator = FileProviderEnumerator(
            containerIdentifier: .rootContainer,
            bridge: bridge
        )

        enumerator.enumerateItems(
            for: observer,
            startingAt: NSFileProviderPage(rawValue: Data())
        )

        require(
            observer.finished.wait(timeout: .now() + 5) == .success,
            "enumeration should finish"
        )
        require(observer.error == nil, "enumeration should not fail")
        require(observer.items.count == 1, "enumeration should surface one snapshot-backed item")
        require(
            awaitValue { await bridge.listedContainerIdentifiers } == [nil],
            "root enumeration should use directory-scoped listing with a nil container identifier"
        )
    }

    static func testTrashEnumeratorSkipsBridgeListing() {
        let bridge = FakeEnumeratorBridge()
        let observer = TestEnumerationObserver()
        let enumerator = FileProviderEnumerator(
            containerIdentifier: NSFileProviderItemIdentifier("NSFileProviderTrashContainerItemIdentifier"),
            bridge: bridge
        )

        enumerator.enumerateItems(
            for: observer,
            startingAt: NSFileProviderPage(rawValue: Data())
        )

        require(
            observer.finished.wait(timeout: .now() + 5) == .success,
            "trash enumeration should finish"
        )
        require(observer.error == nil, "trash enumeration should not fail")
        require(observer.items.isEmpty, "trash enumeration should return no items")
        require(
            awaitValue { await bridge.listedContainerIdentifiers }.isEmpty,
            "trash enumeration should not call into the provider bridge"
        )
    }

    static func testEnumeratorMapsChangesAndAdvancesSyncAnchor() {
        let snapshot = ProviderItemSnapshot(
            rootId: UUID(uuidString: "00741C18-F05F-45F2-8F54-4C1C84A7BC14")!,
            providerId: "hc:v2:file:file-789",
            parentProviderId: "hc:v2:dir:projects",
            relativePath: "Projects/spec.txt",
            kind: .file,
            logicalSize: 128,
            encryptedSize: 256,
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_200),
            contentVersion: Data([0x10]),
            metadataVersion: Data([0x20]),
            identity: FileIdentityV1(
                version: 1,
                rootId: UUID(uuidString: "00741C18-F05F-45F2-8F54-4C1C84A7BC14")!,
                kind: .file,
                relativePath: "Projects/spec.txt",
                pathHashHex: "filehash",
                fileId: "file-789",
                epochId: 9
            )
        )
        let batch = ProviderChangeBatch(
            latestSyncAnchor: 12,
            syncAnchorExpired: false,
            records: [
                ProviderChangeRecord(
                    anchor: 10,
                    kind: .upsert,
                    providerId: snapshot.providerId,
                    parentProviderId: snapshot.parentProviderId,
                    relativePath: snapshot.relativePath,
                    snapshot: snapshot
                ),
                ProviderChangeRecord(
                    anchor: 11,
                    kind: .delete,
                    providerId: "hc:v2:file:deleted-001",
                    parentProviderId: "hc:v2:dir:projects",
                    relativePath: "Projects/deleted.txt",
                    snapshot: nil
                )
            ]
        )
        let bridge = FakeEnumeratorBridge(changeBatch: batch)
        let observer = TestChangeObserver()
        let enumerator = FileProviderEnumerator(
            containerIdentifier: .workingSet,
            bridge: bridge
        )

        enumerator.enumerateChanges(
            for: observer,
            from: ProviderSyncAnchorCodec.encode(9)
        )

        require(
            observer.finished.wait(timeout: .now() + 5) == .success,
            "change enumeration should finish"
        )
        require(observer.error == nil, "change enumeration should not fail")
        require(
            awaitValue { await bridge.requestedAnchors } == [9],
            "change enumeration should request deltas from the decoded sync anchor"
        )
        require(observer.updatedItems.count == 1, "change enumeration should surface upserted items")
        require(observer.deletedIdentifiers == [NSFileProviderItemIdentifier("hc:v2:file:deleted-001")], "change enumeration should surface deleted identifiers")
        require(
            observer.finishedAnchor?.rawValue == ProviderSyncAnchorCodec.encode(12).rawValue,
            "change enumeration should advance to the latest sync anchor"
        )
    }

    static func testEnumeratorMapsBridgeConnectionFailureToFileProviderError() {
        let bridge = FakeEnumeratorBridge(
            listDirectoryError: ProviderBridgeError.connectFailed("Connection refused")
        )
        let observer = TestEnumerationObserver()
        let enumerator = FileProviderEnumerator(
            containerIdentifier: .rootContainer,
            bridge: bridge
        )

        enumerator.enumerateItems(
            for: observer,
            startingAt: NSFileProviderPage(rawValue: Data())
        )

        require(
            observer.finished.wait(timeout: .now() + 5) == .success,
            "failed enumeration should finish"
        )
        let error = observer.error as NSError?
        require(error?.domain == NSFileProviderErrorDomain, "bridge failures should map to NSFileProviderErrorDomain")
        require(
            error?.code == NSFileProviderError.Code.serverUnreachable.rawValue,
            "bridge connection failures should map to serverUnreachable"
        )
    }
}
