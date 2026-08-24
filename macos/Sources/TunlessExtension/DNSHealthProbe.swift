import Foundation

/// Sends one DNS query along the exact path a captured port-53 flow takes.
///
/// The check that matters is not "is the upstream listening" — that stays true
/// while DNS is dead — but "does a query put through this upstream to this
/// resolver come back". So the probe reuses `SOCKSConnection` and the
/// configured resolver rather than testing anything of its own: if this
/// succeeds, a captured TCP port-53 flow would have succeeded too, and if it
/// fails, resolution on the host is failing in the same way.
///
/// TCP rather than UDP, because UDP ASSOCIATE is the part upstreams most often
/// refuse while still relaying DNS correctly, and a probe that reported that
/// as a broken datapath would disable capture on a host where DNS works.
enum DNSHealthProbe {
    static func run(configuration: ProviderConfiguration, timeoutSeconds: TimeInterval = 6) async -> Bool {
        guard let dnsHost = configuration.dnsHost, let dnsPort = configuration.dnsPort else {
            // Without a DNS override, capture does not touch port 53 and there
            // is no resolver path of ours that can fail.
            return true
        }
        let transactionID = UInt16.random(in: 1...UInt16.max)
        let connection = SOCKSConnection(configuration: configuration)
        defer { Task { await connection.cancel() } }
        do {
            return try await withThrowingTaskGroup(of: Bool.self) { group in
                group.addTask {
                    _ = try await connection.open(
                        configuration: configuration,
                        command: 1,
                        destination: SOCKSAddress(host: dnsHost, port: dnsPort),
                        timeoutSeconds: timeoutSeconds)
                    try await connection.send(
                        DNSProbeMessage.tcpFramed(DNSProbeMessage.query(transactionID: transactionID)))
                    let prefix = try await connection.receive(2)
                    guard let length = DNSProbeMessage.tcpPayloadLength(prefix), length > 0 else { return false }
                    let body = try await connection.receive(min(length, 4096))
                    return DNSProbeMessage.isResponse(body, transactionID: transactionID)
                }
                group.addTask {
                    try await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                    await connection.cancel()
                    return false
                }
                defer { group.cancelAll() }
                return try await group.next() ?? false
            }
        } catch {
            return false
        }
    }
}
