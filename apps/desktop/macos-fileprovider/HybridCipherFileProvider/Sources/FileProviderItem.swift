import FileProvider
import Foundation
import UniformTypeIdentifiers

final class FileProviderRootItem: NSObject, NSFileProviderItem {
    private let displayName: String
    private let versionData = Data("hybridcipher-root-v1".utf8)

    init(displayName: String) {
        self.displayName = displayName
        super.init()
    }

    var itemIdentifier: NSFileProviderItemIdentifier {
        .rootContainer
    }

    var parentItemIdentifier: NSFileProviderItemIdentifier {
        .rootContainer
    }

    var filename: String {
        displayName
    }

    var contentType: UTType {
        .folder
    }

    var capabilities: NSFileProviderItemCapabilities {
        [.allowsReading, .allowsContentEnumerating, .allowsAddingSubItems]
    }

    var itemVersion: NSFileProviderItemVersion {
        NSFileProviderItemVersion(contentVersion: versionData, metadataVersion: versionData)
    }
}

final class FileProviderItem: NSObject, NSFileProviderItem {
    let snapshot: ProviderItemSnapshot

    init(snapshot: ProviderItemSnapshot) {
        self.snapshot = snapshot
        super.init()
    }

    var itemIdentifier: NSFileProviderItemIdentifier {
        NSFileProviderItemIdentifier(snapshot.providerId)
    }

    var parentItemIdentifier: NSFileProviderItemIdentifier {
        snapshot.parentProviderId.map { NSFileProviderItemIdentifier($0) } ?? .rootContainer
    }

    var filename: String {
        guard !snapshot.relativePath.isEmpty else {
            return "HybridCipher"
        }
        return (snapshot.relativePath as NSString).lastPathComponent
    }

    var contentType: UTType {
        snapshot.kind == .directory ? .folder : (UTType(filenameExtension: (filename as NSString).pathExtension) ?? .data)
    }

    var documentSize: NSNumber? {
        snapshot.kind == .file ? NSNumber(value: snapshot.logicalSize) : nil
    }

    var childItemCount: NSNumber? {
        snapshot.kind == .directory ? nil : 0
    }

    var capabilities: NSFileProviderItemCapabilities {
        if snapshot.kind == .directory {
            return [.allowsReading, .allowsContentEnumerating, .allowsAddingSubItems, .allowsRenaming, .allowsDeleting]
        }
        return [.allowsReading, .allowsWriting, .allowsRenaming, .allowsDeleting]
    }

    var itemVersion: NSFileProviderItemVersion {
        NSFileProviderItemVersion(
            contentVersion: snapshot.contentVersion,
            metadataVersion: snapshot.metadataVersion
        )
    }

    var extendedAttributes: [String: Data] {
        ["com.hybridcipher.identity.v1": (try? JSONEncoder().encode(snapshot.identity)) ?? Data()]
    }

    var creationDate: Date? {
        snapshot.modifiedAt
    }

    var contentModificationDate: Date? {
        snapshot.modifiedAt
    }
}
