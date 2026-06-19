import FileProvider
import Foundation
import UniformTypeIdentifiers

final class HybridCipherFileProviderExtension: NSObject, NSFileProviderReplicatedExtension {
    private let domain: NSFileProviderDomain
    private let rootId: UUID
    private let bridge: ProviderBridgeClient

    required init(domain: NSFileProviderDomain) {
        self.domain = domain
        self.rootId = UUID(uuidString: domain.identifier.rawValue.replacingOccurrences(of: "com.hybridcipher.root.", with: "")) ?? UUID()
        self.bridge = try! ProviderBridgeClient(rootId: self.rootId)
        super.init()
    }

    func invalidate() {}

    func item(
        for identifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        Task {
            do {
                if identifier == .rootContainer {
                    completionHandler(FileProviderRootItem(displayName: domain.displayName), nil)
                } else if let snapshot = try await bridge.item(identifier: identifier.rawValue) {
                    completionHandler(FileProviderItem(snapshot: snapshot), nil)
                } else {
                    completionHandler(nil, NSFileProviderError(.noSuchItem))
                }
                progress.completedUnitCount = 1
            } catch {
                completionHandler(nil, providerCompatibleError(error))
            }
        }
        return progress
    }

    func enumerator(
        for containerItemIdentifier: NSFileProviderItemIdentifier,
        request: NSFileProviderRequest
    ) throws -> NSFileProviderEnumerator {
        FileProviderEnumerator(containerIdentifier: containerItemIdentifier, bridge: bridge)
    }

    func fetchContents(
        for itemIdentifier: NSFileProviderItemIdentifier,
        version requestedVersion: NSFileProviderItemVersion?,
        request: NSFileProviderRequest,
        completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        Task {
            do {
                let temporaryDirectory = FileManager.default.temporaryDirectory
                    .appendingPathComponent("HybridCipherFileProvider", isDirectory: true)
                try FileManager.default.createDirectory(
                    at: temporaryDirectory,
                    withIntermediateDirectories: true
                )
                let outputURL = temporaryDirectory
                    .appendingPathComponent(UUID().uuidString)
                    .appendingPathExtension("download")
                let snapshot = try await bridge.hydrate(
                    identifier: itemIdentifier.rawValue,
                    outputURL: outputURL
                )
                completionHandler(outputURL, snapshot.map(FileProviderItem.init(snapshot:)), nil)
                progress.completedUnitCount = 1
            } catch {
                completionHandler(nil, nil, providerCompatibleError(error))
            }
        }
        return progress
    }

    func createItem(
        basedOn itemTemplate: NSFileProviderItem,
        fields: NSFileProviderItemFields,
        contents url: URL?,
        options: NSFileProviderCreateItemOptions = [],
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        Task {
            do {
                let relativePath = try await relativePath(for: itemTemplate)
                let action = try ProviderOperationPlanner.createAction(
                    identifier: relativePath,
                    relativePath: relativePath,
                    kind: kind(for: itemTemplate),
                    contentsURL: url
                )
                let snapshot = try await performAction(action, fallbackIdentifier: relativePath)
                completionHandler(FileProviderItem(snapshot: snapshot), [], false, nil)
                progress.completedUnitCount = 1
            } catch {
                completionHandler(nil, fields, false, providerCompatibleError(error))
            }
        }
        return progress
    }

    func modifyItem(
        _ item: NSFileProviderItem,
        baseVersion version: NSFileProviderItemVersion,
        changedFields: NSFileProviderItemFields,
        contents newContents: URL?,
        options: NSFileProviderModifyItemOptions = [],
        request: NSFileProviderRequest,
        completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        Task {
            do {
                let relativePath = try await relativePath(for: item)
                let metadataOnlyChange =
                    changedFields.contains(.filename) || changedFields.contains(.parentItemIdentifier)
                let action = try ProviderOperationPlanner.modifyAction(
                    identifier: item.itemIdentifier.rawValue,
                    relativePath: relativePath,
                    kind: kind(for: item),
                    contentsURL: newContents,
                    metadataOnlyChange: metadataOnlyChange
                )
                if case .noop = action {
                    completionHandler(item, [], false, nil)
                    progress.completedUnitCount = 1
                    return
                }
                let snapshot = try await performAction(action, fallbackIdentifier: item.itemIdentifier.rawValue)
                completionHandler(FileProviderItem(snapshot: snapshot), [], false, nil)
                progress.completedUnitCount = 1
            } catch {
                completionHandler(nil, changedFields, false, providerCompatibleError(error))
            }
        }
        return progress
    }

    func deleteItem(
        identifier: NSFileProviderItemIdentifier,
        baseVersion version: NSFileProviderItemVersion,
        options: NSFileProviderDeleteItemOptions = [],
        request: NSFileProviderRequest,
        completionHandler: @escaping (Error?) -> Void
    ) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        Task {
            do {
                try await bridge.delete(identifier: identifier.rawValue)
                completionHandler(nil)
                progress.completedUnitCount = 1
            } catch {
                completionHandler(providerCompatibleError(error))
            }
        }
        return progress
    }

    private func relativePath(for item: NSFileProviderItem) async throws -> String {
        try await relativePath(
            parentIdentifier: item.parentItemIdentifier,
            filename: item.filename
        )
    }

    private func relativePath(
        parentIdentifier: NSFileProviderItemIdentifier,
        filename: String
    ) async throws -> String {
        let normalizedFilename = normalizeRelativePathComponent(filename)
        if parentIdentifier == .rootContainer {
            return normalizedFilename
        }
        guard let parentSnapshot = try await bridge.item(identifier: parentIdentifier.rawValue) else {
            throw NSFileProviderError(.noSuchItem)
        }
        if parentSnapshot.relativePath.isEmpty {
            return normalizedFilename
        }
        return "\(parentSnapshot.relativePath)/\(normalizedFilename)"
    }

    private func normalizeRelativePathComponent(_ component: String) -> String {
        component
            .replacingOccurrences(of: "\\", with: "/")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    private func kind(for item: NSFileProviderItem) -> ProviderEntryKind {
        item.contentType?.conforms(to: .folder) == true ? .directory : .file
    }

    private func performAction(
        _ action: ProviderOperationAction,
        fallbackIdentifier: String
    ) async throws -> ProviderItemSnapshot {
        switch action {
        case .createDirectory(let relativePath):
            guard let snapshot = try await bridge.createDirectory(relativePath: relativePath) else {
                throw NSFileProviderError(.cannotSynchronize)
            }
            return snapshot
        case .writeback(let identifier, let relativePath, let contentsURL):
            let stagedURL = try ProviderWritebackStager.stage(contentsURL: contentsURL, rootId: rootId)
            defer {
                ProviderWritebackStager.cleanup(stagedURL)
            }
            guard let snapshot = try await bridge.writeback(
                identifier: identifier,
                relativePath: relativePath,
                contentsURL: stagedURL
            ) else {
                throw NSFileProviderError(.cannotSynchronize)
            }
            return snapshot
        case .rename(let identifier, let targetRelativePath):
            if let snapshot = try await bridge.rename(
                identifier: identifier,
                targetRelativePath: targetRelativePath,
                contentsURL: nil
            ) {
                return snapshot
            }
            if let fallback = try await bridge.item(identifier: identifier) {
                return fallback
            }
            if let fallback = try await bridge.item(identifier: fallbackIdentifier) {
                return fallback
            }
            throw NSFileProviderError(.cannotSynchronize)
        case .noop:
            throw NSFileProviderError(.cannotSynchronize)
        }
    }
}
