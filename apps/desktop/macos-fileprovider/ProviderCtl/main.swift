import FileProvider
import Foundation

func json(_ ok: Bool, _ message: String) {
    let escaped = message
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\n", with: "\\n")
        .replacingOccurrences(of: "\r", with: "\\r")
        .replacingOccurrences(of: "\t", with: "\\t")
    print("{\"message\":\"\(escaped)\",\"ok\":\(ok ? "true" : "false")}")
}

func fail(_ message: String, code: Int32 = 2) -> Never {
    json(false, message)
    Foundation.exit(code)
}

enum ProviderCtlError: LocalizedError {
    case missingOption(String)
    case unknownOption(String)
    case domainNotFound(String)
    case managerUnavailable(String)
    case timedOut(String)

    var errorDescription: String? {
        switch self {
        case .missingOption(let option):
            return "missing required option: \(option)"
        case .unknownOption(let option):
            return "unknown option: \(option)"
        case .domainNotFound(let domainIdentifier):
            return "File Provider domain not found: \(domainIdentifier)"
        case .managerUnavailable(let domainIdentifier):
            return "File Provider manager unavailable for domain: \(domainIdentifier)"
        case .timedOut(let operation):
            return "\(operation) timed out waiting for File Provider"
        }
    }
}

private let rootContainerSignalIdentifier = "__hybridcipher_root_container__"

struct SignalArguments {
    let domainIdentifier: String
    let containerIdentifiers: [String]
}

struct RegisterArguments {
    let domainIdentifier: String
    let displayName: String
}

struct DomainArguments {
    let domainIdentifier: String
}

func waitForFileProvider(_ operation: String, _ block: (@escaping (Error?) -> Void) -> Void) throws {
    let semaphore = DispatchSemaphore(value: 0)
    var capturedError: Error?
    block { error in
        capturedError = error
        semaphore.signal()
    }
    if semaphore.wait(timeout: .now() + 30) == .timedOut {
        throw ProviderCtlError.timedOut(operation)
    }
    if let capturedError {
        throw capturedError
    }
}

func parseSignalArguments(_ arguments: ArraySlice<String>) throws -> SignalArguments {
    var domainIdentifier: String?
    var containerIdentifiers: [String] = []
    var index = arguments.startIndex

    while index < arguments.endIndex {
        let argument = arguments[index]
        switch argument {
        case "--domain-id":
            index = arguments.index(after: index)
            guard index < arguments.endIndex else {
                throw ProviderCtlError.missingOption("--domain-id")
            }
            domainIdentifier = arguments[index]
        case "--container-id":
            index = arguments.index(after: index)
            guard index < arguments.endIndex else {
                throw ProviderCtlError.missingOption("--container-id")
            }
            containerIdentifiers.append(arguments[index])
        default:
            throw ProviderCtlError.unknownOption(argument)
        }
        index = arguments.index(after: index)
    }

    guard let domainIdentifier else {
        throw ProviderCtlError.missingOption("--domain-id")
    }

    return SignalArguments(
        domainIdentifier: domainIdentifier,
        containerIdentifiers: containerIdentifiers
    )
}

func parseRegisterArguments(_ arguments: ArraySlice<String>) throws -> RegisterArguments {
    var domainIdentifier: String?
    var displayName: String?
    var index = arguments.startIndex

    while index < arguments.endIndex {
        let argument = arguments[index]
        switch argument {
        case "--domain-id":
            index = arguments.index(after: index)
            guard index < arguments.endIndex else {
                throw ProviderCtlError.missingOption("--domain-id")
            }
            domainIdentifier = arguments[index]
        case "--display-name":
            index = arguments.index(after: index)
            guard index < arguments.endIndex else {
                throw ProviderCtlError.missingOption("--display-name")
            }
            displayName = arguments[index]
        default:
            throw ProviderCtlError.unknownOption(argument)
        }
        index = arguments.index(after: index)
    }

    guard let domainIdentifier else {
        throw ProviderCtlError.missingOption("--domain-id")
    }

    return RegisterArguments(
        domainIdentifier: domainIdentifier,
        displayName: displayName ?? "HybridCipher"
    )
}

func parseDomainArguments(_ arguments: ArraySlice<String>) throws -> DomainArguments {
    var domainIdentifier: String?
    var index = arguments.startIndex

    while index < arguments.endIndex {
        let argument = arguments[index]
        switch argument {
        case "--domain-id":
            index = arguments.index(after: index)
            guard index < arguments.endIndex else {
                throw ProviderCtlError.missingOption("--domain-id")
            }
            domainIdentifier = arguments[index]
        default:
            throw ProviderCtlError.unknownOption(argument)
        }
        index = arguments.index(after: index)
    }

    guard let domainIdentifier else {
        throw ProviderCtlError.missingOption("--domain-id")
    }

    return DomainArguments(domainIdentifier: domainIdentifier)
}

func loadDomains() throws -> [NSFileProviderDomain] {
    let semaphore = DispatchSemaphore(value: 0)
    var domains: [NSFileProviderDomain] = []
    var capturedError: Error?

    NSFileProviderManager.getDomainsWithCompletionHandler { resolvedDomains, error in
        domains = resolvedDomains
        capturedError = error
        semaphore.signal()
    }
    if semaphore.wait(timeout: .now() + 30) == .timedOut {
        throw ProviderCtlError.timedOut("list File Provider domains")
    }

    if let capturedError {
        throw capturedError
    }

    return domains
}

func findDomain(_ domainIdentifier: String) throws -> NSFileProviderDomain? {
    try loadDomains().first(where: { $0.identifier.rawValue == domainIdentifier })
}

func registerDomain(_ arguments: RegisterArguments) throws {
    if try findDomain(arguments.domainIdentifier) != nil {
        return
    }

    let domain = NSFileProviderDomain(
        identifier: NSFileProviderDomainIdentifier(arguments.domainIdentifier),
        displayName: arguments.displayName
    )
    try waitForFileProvider("register File Provider domain") { completion in
        NSFileProviderManager.add(domain, completionHandler: completion)
    }
}

func unregisterDomain(_ arguments: DomainArguments) throws {
    guard let domain = try findDomain(arguments.domainIdentifier) else {
        return
    }

    try waitForFileProvider("unregister File Provider domain") { completion in
        NSFileProviderManager.remove(domain, completionHandler: completion)
    }
}

func signalEnumerators(
    manager: NSFileProviderManager,
    identifiers: [NSFileProviderItemIdentifier]
) throws {
    for identifier in identifiers {
        let semaphore = DispatchSemaphore(value: 0)
        var capturedError: Error?
        manager.signalEnumerator(for: identifier) { error in
            capturedError = error
            semaphore.signal()
        }
        semaphore.wait()
        if let capturedError {
            throw capturedError
        }
    }
}

func signalDomain(_ arguments: SignalArguments) throws {
    let domains = try loadDomains()
    guard let domain = domains.first(where: { $0.identifier.rawValue == arguments.domainIdentifier }) else {
        throw ProviderCtlError.domainNotFound(arguments.domainIdentifier)
    }
    guard let manager = NSFileProviderManager(for: domain) else {
        throw ProviderCtlError.managerUnavailable(arguments.domainIdentifier)
    }

    var identifiers: [NSFileProviderItemIdentifier] = [.workingSet]
    for containerIdentifier in arguments.containerIdentifiers {
        if containerIdentifier == NSFileProviderItemIdentifier.workingSet.rawValue {
            continue
        }
        if containerIdentifier == rootContainerSignalIdentifier {
            identifiers.append(.rootContainer)
            continue
        }
        identifiers.append(NSFileProviderItemIdentifier(containerIdentifier))
    }

    try signalEnumerators(manager: manager, identifiers: identifiers)
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else {
    fail("usage: providerctl-native <status|signal|domains|register|unregister>")
}

switch command {
case "status":
    json(true, "macos-file-provider helper available")

case "domains":
    do {
        let domains = try loadDomains().map { $0.identifier.rawValue }.sorted()
        json(true, domains.joined(separator: "\n"))
    } catch {
        fail(error.localizedDescription)
    }

case "register":
    do {
        let registerArguments = try parseRegisterArguments(arguments.dropFirst())
        try registerDomain(registerArguments)
        json(true, "registered File Provider domain")
    } catch {
        fail(error.localizedDescription)
    }

case "unregister":
    do {
        let unregisterArguments = try parseDomainArguments(arguments.dropFirst())
        try unregisterDomain(unregisterArguments)
        json(true, "unregistered File Provider domain")
    } catch {
        fail(error.localizedDescription)
    }

case "signal":
    do {
        let signalArguments = try parseSignalArguments(arguments.dropFirst())
        try signalDomain(signalArguments)
        json(true, "signaled File Provider enumerators")
    } catch {
        fail(error.localizedDescription)
    }
default:
    fail("unknown providerctl-native command: \(command)")
}
