import Foundation

enum ProviderWritebackStagerError: Error, LocalizedError {
    case appGroupUnavailable(String)

    var errorDescription: String? {
        switch self {
        case .appGroupUnavailable(let group):
            return "App group container is unavailable for File Provider writeback staging: \(group)"
        }
    }
}

enum ProviderWritebackStager {
    private static let stagingDirectoryName = "writeback"
    private static let temporaryPrefix = ".hybridcipher-writeback-"

    static func stage(
        contentsURL: URL,
        rootId: UUID,
        fileManager: FileManager = .default
    ) throws -> URL {
        let groupIdentifier = ProviderAppGroup.identifier()
        guard let container = ProviderAppGroup.containerURL(fileManager: fileManager) else {
            throw ProviderWritebackStagerError.appGroupUnavailable(groupIdentifier)
        }
        let stagingRoot = container.appendingPathComponent(stagingDirectoryName, isDirectory: true)
        return try stage(
            contentsURL: contentsURL,
            rootId: rootId,
            stagingRoot: stagingRoot,
            fileManager: fileManager
        )
    }

    static func stage(
        contentsURL: URL,
        rootId: UUID,
        stagingRoot: URL,
        fileManager: FileManager = .default
    ) throws -> URL {
        let rootDirectory = stagingRoot
            .appendingPathComponent(rootId.uuidString.lowercased(), isDirectory: true)
        try fileManager.createDirectory(at: rootDirectory, withIntermediateDirectories: true)

        var fileName = UUID().uuidString
        let pathExtension = contentsURL.pathExtension.trimmingCharacters(in: .whitespacesAndNewlines)
        if !pathExtension.isEmpty {
            fileName += ".\(pathExtension)"
        }

        let temporaryURL = rootDirectory.appendingPathComponent("\(temporaryPrefix)\(fileName)")
        let stagedURL = rootDirectory.appendingPathComponent(fileName)
        try? fileManager.removeItem(at: temporaryURL)
        try? fileManager.removeItem(at: stagedURL)

        do {
            try fileManager.copyItem(at: contentsURL, to: temporaryURL)
            try fileManager.moveItem(at: temporaryURL, to: stagedURL)
            return stagedURL
        } catch {
            try? fileManager.removeItem(at: temporaryURL)
            try? fileManager.removeItem(at: stagedURL)
            throw error
        }
    }

    static func cleanup(_ stagedURL: URL, fileManager: FileManager = .default) {
        try? fileManager.removeItem(at: stagedURL)
    }
}
