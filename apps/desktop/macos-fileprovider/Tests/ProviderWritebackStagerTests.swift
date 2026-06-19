import Foundation

func require(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        exit(1)
    }
}

@main
struct ProviderWritebackStagerTestRunner {
    static func main() throws {
        let fileManager = FileManager.default
        let testRoot = fileManager.temporaryDirectory
            .appendingPathComponent("HybridCipherProviderWritebackStagerTests-\(UUID().uuidString)", isDirectory: true)
        let stagingRoot = testRoot.appendingPathComponent("shared-staging", isDirectory: true)
        let sourceDirectory = testRoot.appendingPathComponent("provider-private", isDirectory: true)
        let sourceURL = sourceDirectory.appendingPathComponent("Dockerfile")
        let rootId = UUID(uuidString: "00741C18-F05F-45F2-8F54-4C1C84A7BC14")!
        let payload = Data("FROM scratch\n# changed in File Provider\n".utf8)

        defer {
            try? fileManager.removeItem(at: testRoot)
        }

        try fileManager.createDirectory(at: sourceDirectory, withIntermediateDirectories: true)
        try payload.write(to: sourceURL)

        let stagedURL = try ProviderWritebackStager.stage(
            contentsURL: sourceURL,
            rootId: rootId,
            stagingRoot: stagingRoot,
            fileManager: fileManager
        )

        require(stagedURL.path.hasPrefix(stagingRoot.path), "staged file must be inside shared staging root")
        require(fileManager.fileExists(atPath: stagedURL.path), "staged file should exist")
        let stagedPayload = try Data(contentsOf: stagedURL)
        require(stagedPayload == payload, "staged file should copy provider contents exactly")

        try fileManager.removeItem(at: sourceURL)
        let stagedPayloadAfterSourceRemoval = try Data(contentsOf: stagedURL)
        require(stagedPayloadAfterSourceRemoval == payload, "staged copy should survive after provider temp source disappears")

        ProviderWritebackStager.cleanup(stagedURL, fileManager: fileManager)
        require(!fileManager.fileExists(atPath: stagedURL.path), "cleanup should remove staged file")
    }
}
