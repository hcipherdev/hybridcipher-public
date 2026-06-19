import Foundation

enum ProviderAppGroup {
    static let fallbackIdentifier = "G2L88C9692.group.com.hybridcipher.macOS"

    static func identifier(bundle: Bundle = .main) -> String {
        guard
            let extensionInfo = bundle.object(forInfoDictionaryKey: "NSExtension") as? [String: Any],
            let documentGroup = extensionInfo["NSExtensionFileProviderDocumentGroup"] as? String
        else {
            return fallbackIdentifier
        }

        let trimmed = documentGroup.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty || trimmed.contains("$(") {
            return fallbackIdentifier
        }
        return trimmed
    }

    static func containerURL(
        fileManager: FileManager = .default,
        bundle: Bundle = .main
    ) -> URL? {
        fileManager.containerURL(forSecurityApplicationGroupIdentifier: identifier(bundle: bundle))
    }
}
