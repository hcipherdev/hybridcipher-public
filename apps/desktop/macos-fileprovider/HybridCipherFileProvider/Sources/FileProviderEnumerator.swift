import FileProvider
import Foundation

private let trashContainerIdentifier = "NSFileProviderTrashContainerItemIdentifier"

final class FileProviderEnumerator: NSObject, NSFileProviderEnumerator {
    private let containerIdentifier: NSFileProviderItemIdentifier
    private let bridge: any ProviderEnumeratorBridge

    init(containerIdentifier: NSFileProviderItemIdentifier, bridge: any ProviderEnumeratorBridge) {
        self.containerIdentifier = containerIdentifier
        self.bridge = bridge
        super.init()
    }

    func invalidate() {}

    func enumerateItems(
        for observer: NSFileProviderEnumerationObserver,
        startingAt page: NSFileProviderPage
    ) {
        Task {
            do {
                if containerIdentifier == .workingSet ||
                    containerIdentifier.rawValue == trashContainerIdentifier
                {
                    observer.didEnumerate([])
                    observer.finishEnumerating(upTo: nil)
                    return
                }

                let snapshots = try await bridge.listDirectory(
                    containerIdentifier: containerIdentifier == .rootContainer ? nil : containerIdentifier.rawValue
                )
                let items = snapshots.map(FileProviderItem.init(snapshot:))
                observer.didEnumerate(items)
                observer.finishEnumerating(upTo: nil)
            } catch {
                observer.finishEnumeratingWithError(providerCompatibleError(error))
            }
        }
    }

    func enumerateChanges(
        for observer: NSFileProviderChangeObserver,
        from syncAnchor: NSFileProviderSyncAnchor
    ) {
        Task {
            do {
                let batch = try await bridge.changes(
                    sinceAnchor: ProviderSyncAnchorCodec.decode(syncAnchor)
                )
                if batch.syncAnchorExpired {
                    observer.finishEnumeratingWithError(NSFileProviderError(.syncAnchorExpired))
                    return
                }

                let updatedItems = batch.records.compactMap { record -> FileProviderItem? in
                    guard record.kind == .upsert, let snapshot = record.snapshot else {
                        return nil
                    }
                    return FileProviderItem(snapshot: snapshot)
                }
                if !updatedItems.isEmpty {
                    observer.didUpdate(updatedItems)
                }

                let deletedIdentifiers = batch.records.compactMap { record -> NSFileProviderItemIdentifier? in
                    guard record.kind == .delete else {
                        return nil
                    }
                    return NSFileProviderItemIdentifier(record.providerId)
                }
                if !deletedIdentifiers.isEmpty {
                    observer.didDeleteItems(withIdentifiers: deletedIdentifiers)
                }

                observer.finishEnumeratingChanges(
                    upTo: ProviderSyncAnchorCodec.encode(batch.latestSyncAnchor),
                    moreComing: false
                )
            } catch {
                observer.finishEnumeratingWithError(providerCompatibleError(error))
            }
        }
    }

    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        Task {
            do {
                let anchor = try await bridge.currentSyncAnchor()
                completionHandler(ProviderSyncAnchorCodec.encode(anchor))
            } catch {
                completionHandler(nil)
            }
        }
    }
}
