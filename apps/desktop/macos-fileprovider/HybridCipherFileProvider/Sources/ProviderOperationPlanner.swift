import Foundation

enum ProviderOperationPlannerError: LocalizedError {
    case missingFileContents(String)

    var errorDescription: String? {
        switch self {
        case .missingFileContents(let relativePath):
            return "File Provider operation for \(relativePath) requires file contents."
        }
    }
}

enum ProviderOperationAction {
    case createDirectory(relativePath: String)
    case writeback(identifier: String, relativePath: String, contentsURL: URL)
    case rename(identifier: String, targetRelativePath: String)
    case noop
}

enum ProviderOperationPlanner {
    static func createAction(
        identifier: String,
        relativePath: String,
        kind: ProviderEntryKind,
        contentsURL: URL?
    ) throws -> ProviderOperationAction {
        let normalizedRelativePath = normalizeRelativePath(relativePath)
        switch kind {
        case .directory:
            return .createDirectory(relativePath: normalizedRelativePath)
        case .file:
            guard let contentsURL else {
                throw ProviderOperationPlannerError.missingFileContents(normalizedRelativePath)
            }
            return .writeback(
                identifier: normalizeRelativePath(identifier),
                relativePath: normalizedRelativePath,
                contentsURL: contentsURL
            )
        }
    }

    static func modifyAction(
        identifier: String,
        relativePath: String,
        kind: ProviderEntryKind,
        contentsURL: URL?,
        metadataOnlyChange: Bool
    ) throws -> ProviderOperationAction {
        let normalizedIdentifier = normalizeRelativePath(identifier)
        let normalizedRelativePath = normalizeRelativePath(relativePath)

        if let contentsURL {
            return .writeback(
                identifier: normalizedIdentifier,
                relativePath: normalizedRelativePath,
                contentsURL: contentsURL
            )
        }

        if metadataOnlyChange && normalizedIdentifier != normalizedRelativePath {
            return .rename(
                identifier: normalizedIdentifier,
                targetRelativePath: normalizedRelativePath
            )
        }

        let _ = kind
        return .noop
    }

    private static func normalizeRelativePath(_ path: String) -> String {
        path
            .replacingOccurrences(of: "\\", with: "/")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }
}
