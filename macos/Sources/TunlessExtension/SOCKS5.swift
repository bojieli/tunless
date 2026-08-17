import Foundation
import Network

enum SOCKSError: Error { case invalidAddress, invalidReply, rejected(UInt8), authentication, closed }

private final class ContinuationGate:@unchecked Sendable {
	private let lock=NSLock();private var completed=false
	func resume(_ continuation:CheckedContinuation<Void,Error>,result:Result<Void,Error>){lock.lock();guard !completed else{lock.unlock();return};completed=true;lock.unlock();continuation.resume(with:result)}
}

struct SOCKSAddress: Equatable, Sendable {
    let host: String
    let port: UInt16

    func encoded() throws -> Data {
        var out = Data()
        if let v4 = IPv4Address(host) { out.append(1); out.append(contentsOf: v4.rawValue) }
        else if let v6 = IPv6Address(host) { out.append(4); out.append(contentsOf: v6.rawValue) }
        else { let bytes = Data(host.utf8); guard bytes.count <= 255 else { throw SOCKSError.invalidAddress }; out.append(3); out.append(UInt8(bytes.count)); out.append(bytes) }
        out.append(UInt8(port >> 8)); out.append(UInt8(port & 0xff)); return out
    }

    static func decode(_ data: Data, offset: inout Int) throws -> SOCKSAddress {
        guard offset < data.count else { throw SOCKSError.invalidReply }; let type=data[offset];offset += 1
        let host:String
        switch type {
        case 1: guard offset+4<=data.count else{throw SOCKSError.invalidReply};host=IPv4Address(data[offset..<offset+4])!.debugDescription;offset += 4
        case 4: guard offset+16<=data.count else{throw SOCKSError.invalidReply};host=IPv6Address(data[offset..<offset+16])!.debugDescription;offset += 16
        case 3: guard offset<data.count else{throw SOCKSError.invalidReply};let n=Int(data[offset]);offset += 1;guard offset+n<=data.count else{throw SOCKSError.invalidReply};host=String(decoding:data[offset..<offset+n],as:UTF8.self);offset += n
        default: throw SOCKSError.invalidReply
        }
        guard offset+2<=data.count else{throw SOCKSError.invalidReply};let port=UInt16(data[offset])<<8|UInt16(data[offset+1]);offset += 2;return SOCKSAddress(host:host,port:port)
    }
}

actor SOCKSConnection {
    private let connection: NWConnection
    private var buffered = Data()

    init(configuration: ProviderConfiguration) {
        connection = NWConnection(host: NWEndpoint.Host(configuration.upstreamHost), port: NWEndpoint.Port(rawValue: configuration.upstreamPort)!, using: .tcp)
    }

    func open(configuration: ProviderConfiguration, command: UInt8, destination: SOCKSAddress) async throws -> SOCKSAddress {
        connection.start(queue: .global(qos:.userInitiated)); try await ready()
        let hasCredentials=configuration.username != nil || configuration.password != nil;let greeting=Data([5,1,hasCredentials ? 2:0]);try await send(greeting)
        let method=try await receive(2);guard method[0]==5 else{throw SOCKSError.invalidReply}
        if method[1]==2 { guard hasCredentials else{throw SOCKSError.authentication};let user=Data((configuration.username ?? "").utf8),pass=Data((configuration.password ?? "").utf8);guard user.count<256&&pass.count<256 else{throw SOCKSError.authentication};var auth=Data([1,UInt8(user.count)]);auth.append(user);auth.append(UInt8(pass.count));auth.append(pass);try await send(auth);let reply=try await receive(2);guard reply[0]==1&&reply[1]==0 else{throw SOCKSError.authentication} }
        else if method[1]==0 { guard !hasCredentials else{throw SOCKSError.authentication} }
        else { throw SOCKSError.authentication }
        var request=Data([5,command,0]);request.append(try destination.encoded());try await send(request)
        let head=try await receive(4);guard head[0]==5 else{throw SOCKSError.invalidReply};guard head[1]==0 else{throw SOCKSError.rejected(head[1])}
        let addressLength:Int;switch head[3]{case 1:addressLength=4;case 4:addressLength=16;case 3:addressLength=1+Int(try await receive(1)[0]);default:throw SOCKSError.invalidReply}
        var addressData=Data([head[3]]);if head[3]==3{addressData.append(UInt8(addressLength-1))};addressData.append(try await receive(addressLength+(head[3]==3 ? -1:0)+2));var offset=0;return try SOCKSAddress.decode(addressData,offset:&offset)
    }

    func send(_ data: Data) async throws { try await withCheckedThrowingContinuation{ (continuation:CheckedContinuation<Void,Error>) in connection.send(content:data,completion:.contentProcessed{error in if let error{continuation.resume(throwing:error)}else{continuation.resume()}}) } }
	func finishSending()async throws{try await withCheckedThrowingContinuation{(continuation:CheckedContinuation<Void,Error>) in connection.send(content:nil,contentContext:.finalMessage,isComplete:true,completion:.contentProcessed{error in if let error{continuation.resume(throwing:error)}else{continuation.resume()}})}}
    func receive(_ count:Int) async throws -> Data { while buffered.count<count { let part=try await withCheckedThrowingContinuation{(continuation:CheckedContinuation<Data,Error>) in connection.receive(minimumIncompleteLength:1,maximumLength:65535){data,_,done,error in if let error{continuation.resume(throwing:error)}else if let data,!data.isEmpty{continuation.resume(returning:data)}else{continuation.resume(throwing:SOCKSError.closed)}}};buffered.append(part)};let value=buffered.prefix(count);buffered.removeFirst(count);return Data(value) }
    func receiveSome() async throws -> Data { if !buffered.isEmpty { let value=buffered;buffered.removeAll(keepingCapacity:true);return value };return try await withCheckedThrowingContinuation{(continuation:CheckedContinuation<Data,Error>) in connection.receive(minimumIncompleteLength:1,maximumLength:65535){data,_,_,error in if let error{continuation.resume(throwing:error)}else if let data,!data.isEmpty{continuation.resume(returning:data)}else{continuation.resume(throwing:SOCKSError.closed)}}} }
    func cancel(){connection.cancel()}
    private func ready() async throws { try await withCheckedThrowingContinuation{continuation in let gate=ContinuationGate();connection.stateUpdateHandler={state in switch state{case .ready:gate.resume(continuation,result:.success(()));case .failed(let error):gate.resume(continuation,result:.failure(error));case .cancelled:gate.resume(continuation,result:.failure(SOCKSError.closed));default:break}}} }
}
