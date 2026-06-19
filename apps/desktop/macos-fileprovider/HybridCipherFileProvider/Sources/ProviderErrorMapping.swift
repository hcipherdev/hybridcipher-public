import FileProvider
import Foundation

func providerCompatibleError(_ error: Error) -> Error {
    let nsError = error as NSError
    if nsError.domain == NSFileProviderErrorDomain {
        return error
    }

    if let bridgeError = error as? ProviderBridgeError {
        switch bridgeError {
        case .appGroupUnavailable,
             .socketPathTooLong,
             .connectFailed,
             .writeFailed,
             .readFailed:
            return NSFileProviderError(.serverUnreachable)
        case .providerRejected:
            return NSFileProviderError(.cannotSynchronize)
        }
    }

    if nsError.domain == NSPOSIXErrorDomain || nsError.domain == NSURLErrorDomain {
        return NSFileProviderError(.serverUnreachable)
    }

    return NSFileProviderError(.cannotSynchronize)
}
