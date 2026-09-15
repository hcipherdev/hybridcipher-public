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
        testMoveToTrashUsesDeleteAction()
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

    static func testMoveToTrashUsesDeleteAction() {
        let action = try! ProviderOperationPlanner.modifyAction(
            identifier: "hc:v2:file:pending:path-hash",
            relativePath: "draft.txt",
            kind: .file,
            contentsURL: nil,
            metadataOnlyChange: true,
            parentIdentifier: fileProviderTrashContainerIdentifier
        )

        switch action {
        case .delete(let identifier):
            require(
                identifier == "hc:v2:file:pending:path-hash",
                "trash moves should preserve the provider identifier for deletion"
            )
        default:
            require(false, "moving an item to File Provider Trash should become a delete")
        }
    }
}
