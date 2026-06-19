import Foundation

func require(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() {
        FileHandle.standardError.write(Data("FAIL: \(message)\n".utf8))
        exit(1)
    }
}

@main
struct ProviderOperationPlannerTestRunner {
    static func main() throws {
        testCreateDirectoryWithoutContentsUsesDirectoryAction()
        testMetadataOnlyRenameUsesRenameAction()
    }

    static func testCreateDirectoryWithoutContentsUsesDirectoryAction() {
        let action = try! ProviderOperationPlanner.createAction(
            identifier: "Projects",
            relativePath: "Projects",
            kind: .directory,
            contentsURL: nil
        )

        switch action {
        case .createDirectory(let relativePath):
            require(relativePath == "Projects", "directory create should keep the target path")
        default:
            require(false, "directory create should not require file contents")
        }
    }

    static func testMetadataOnlyRenameUsesRenameAction() {
        let action = try! ProviderOperationPlanner.modifyAction(
            identifier: "draft.txt",
            relativePath: "renamed.txt",
            kind: .file,
            contentsURL: nil,
            metadataOnlyChange: true
        )

        switch action {
        case .rename(let identifier, let targetRelativePath):
            require(identifier == "draft.txt", "rename should preserve the source identifier")
            require(targetRelativePath == "renamed.txt", "rename should use the new relative path")
        default:
            require(false, "metadata-only rename should not become a no-op")
        }
    }
}
