import Foundation
import Network
import NetworkExtension

public final class TransparentProxyProvider: NETransparentProxyProvider, NEAppProxyUDPFlowHandling {
	private enum PumpResult { case applicationEOF(String), networkEOF, failed(String) }
    private var configuration = ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:7890)
    private var telemetry:[FlowTelemetry]=[]
    private let lock=NSLock()

    public override func startProxy(options:[String:Any]? = nil, completionHandler:@escaping(Error?)->Void) {
		guard let dictionary=(protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,let raw=dictionary["configuration"] as? Data,let parsed=try? JSONDecoder().decode(ProviderConfiguration.self,from:raw),let validated=try? parsed.validated() else { completionHandler(ConfigurationError.invalidUpstream);return }
        configuration=validated
        let settings=NETransparentProxyNetworkSettings(tunnelRemoteAddress:"127.0.0.1")
        let anyPort=NWEndpoint.Port(rawValue:0)!
        // A transparent-proxy rule cannot combine an any-port endpoint with a
        // wildcard address. Non-zero hosts masked to /1 cover both IP families.
        settings.includedNetworkRules=[
            NENetworkRule(destinationNetworkEndpoint:.hostPort(host:"0.0.0.1",port:anyPort),prefix:1,protocol:.any),
            NENetworkRule(destinationNetworkEndpoint:.hostPort(host:"128.0.0.1",port:anyPort),prefix:1,protocol:.any),
            NENetworkRule(destinationNetworkEndpoint:.hostPort(host:"::2",port:anyPort),prefix:1,protocol:.any),
            NENetworkRule(destinationNetworkEndpoint:.hostPort(host:"8000::1",port:anyPort),prefix:1,protocol:.any),
        ]
        setTunnelNetworkSettings(settings,completionHandler:completionHandler)
    }

    public override func stopProxy(with reason:NEProviderStopReason,completionHandler:@escaping()->Void){completionHandler()}

    public override func handleNewFlow(_ flow:NEAppProxyFlow)->Bool {
		if let tcp=flow as? NEAppProxyTCPFlow,let destination=Self.address(tcp.remoteFlowEndpoint) {
			let selected=configurationSnapshot();guard selected.captures(host:destination.host,signingIdentifier:flow.metaData.sourceAppSigningIdentifier) else{return false}
			let routeHost=(tcp.remoteHostname?.isEmpty == false ? tcp.remoteHostname : nil) ?? destination.host
			let requestedDestination=SOCKSAddress(host:routeHost,port:destination.port)
			let routeDestination=selected.routedDestination(for:requestedDestination)
			record(flow:flow,destination:destination,routedDestination:routeDestination);Task{await handleTCP(tcp,destination:routeDestination,configuration:selected)};return true
		}
        return false
    }

    public func handleNewUDPFlow(_ flow:NEAppProxyUDPFlow,initialRemoteFlowEndpoint remoteEndpoint:Network.NWEndpoint)->Bool{let destination=Self.address(remoteEndpoint) ?? SOCKSAddress(host:"0.0.0.0",port:0);let selected=configurationSnapshot();guard selected.captures(host:destination.host,signingIdentifier:flow.metaData.sourceAppSigningIdentifier)else{return false};Task{await handleUDP(flow,configuration:selected)};return true}

    public override func handleAppMessage(_ messageData:Data,completionHandler:((Data?)->Void)?=nil){
        if let updated=try? JSONDecoder().decode(ProviderConfiguration.self,from:messageData),let validated=try? updated.validated(){lock.lock();configuration=validated;lock.unlock();completionHandler?(Data());return}
        lock.lock();let snapshot=telemetry;telemetry.removeAll(keepingCapacity:true);lock.unlock();completionHandler?(try? JSONEncoder().encode(snapshot))
    }

    private func handleTCP(_ flow:NEAppProxyTCPFlow,destination:SOCKSAddress,configuration:ProviderConfiguration) async {
        do { try await open(flow);let socks=SOCKSConnection(configuration:configuration);_ = try await socks.open(configuration:configuration,command:1,destination:destination)
			let outcome=await withTaskGroup(of:PumpResult.self){group->String in
				group.addTask{await Self.appToNetwork(flow,socks:socks)}
				group.addTask{await Self.networkToApp(socks:socks,flow:flow)}
				guard let first=await group.next() else{return "no-pump-result"}
				switch first {
				case .networkEOF:
					flow.closeWriteWithError(nil);flow.closeReadWithError(nil);await socks.cancel();group.cancelAll();return "network-eof-first"
				case .failed(let detail):
					flow.closeWriteWithError(SOCKSError.closed);flow.closeReadWithError(SOCKSError.closed);await socks.cancel();group.cancelAll();return "failed-first:\(detail)"
				case .applicationEOF(let detail):
					flow.closeWriteWithError(nil);flow.closeReadWithError(nil);await socks.cancel();group.cancelAll();return "application-eof:\(detail)"
				}
			}
			recordCompletion(flow:flow,destination:destination,event:outcome)
        } catch { recordCompletion(flow:flow,destination:destination,event:"setup-error:\(error)");flow.closeReadWithError(error);flow.closeWriteWithError(error) }
    }

    private func handleUDP(_ flow:NEAppProxyUDPFlow,configuration:ProviderConfiguration) async {
		do { try await open(flow);let control=SOCKSConnection(configuration:configuration);var relay=try await control.open(configuration:configuration,command:3,destination:SOCKSAddress(host:"0.0.0.0",port:0));if Self.unspecified(relay.host) || (Self.loopback(relay.host) && !Self.loopback(configuration.upstreamHost)){relay=SOCKSAddress(host:configuration.upstreamHost,port:relay.port)};guard relay.port > 0 else{throw SOCKSError.invalidAddress};let datagrams=NWConnection(host:NWEndpoint.Host(relay.host),port:NWEndpoint.Port(rawValue:relay.port)!,using:.udp);let dnsResponses=DNSResponseMap();datagrams.start(queue:.global(qos:.userInitiated))
			await withTaskGroup(of:Void.self){group in group.addTask{await self.appToUDP(flow,connection:datagrams,configuration:configuration,dnsResponses:dnsResponses)};group.addTask{await self.udpToApp(datagrams,flow:flow,dnsResponses:dnsResponses)};group.addTask{_ = try? await control.receiveSome()};await group.next();datagrams.cancel();await control.cancel();flow.closeReadWithError(nil);flow.closeWriteWithError(nil);group.cancelAll()}
        } catch { flow.closeReadWithError(error);flow.closeWriteWithError(error) }
    }

    private func record(flow:NEAppProxyFlow,destination:SOCKSAddress,routedDestination:SOCKSAddress){let routed=routedDestination == destination ? nil : "\(routedDestination.host):\(routedDestination.port)";let item=FlowTelemetry(protocolName:flow is NEAppProxyTCPFlow ? "tcp":"udp",destination:"\(destination.host):\(destination.port)",routedDestination:routed,hostname:flow.remoteHostname,signingIdentifier:flow.metaData.sourceAppSigningIdentifier,timestamp:Date(),event:nil);appendTelemetry(item)}
	private func recordCompletion(flow:NEAppProxyFlow,destination:SOCKSAddress,event:String){let item=FlowTelemetry(protocolName:"tcp-completion",destination:"\(destination.host):\(destination.port)",routedDestination:nil,hostname:flow.remoteHostname,signingIdentifier:flow.metaData.sourceAppSigningIdentifier,timestamp:Date(),event:event);appendTelemetry(item)}
	private func appendTelemetry(_ item:FlowTelemetry){lock.lock();if telemetry.count>=4096{telemetry.removeFirst(1024)};telemetry.append(item);lock.unlock()}
	private func configurationSnapshot()->ProviderConfiguration{lock.lock();defer{lock.unlock()};return configuration}
    private static func address(_ endpoint:Network.NWEndpoint)->SOCKSAddress?{if case let .hostPort(host,port)=endpoint{return SOCKSAddress(host:host.debugDescription,port:port.rawValue)};return nil}
	private static func unspecified(_ host:String)->Bool{host=="0.0.0.0" || host=="::"}
	private static func loopback(_ host:String)->Bool{if host.lowercased()=="localhost"{return true};if let address=IPv4Address(host){return address.rawValue.first==127};if let address=IPv6Address(host){return address.rawValue==IPv6Address("::1")!.rawValue};return false}
    private func open(_ flow:NEAppProxyFlow)async throws{try await withCheckedThrowingContinuation{(continuation:CheckedContinuation<Void,Error>) in flow.open(withLocalFlowEndpoint:nil){error in if let error{continuation.resume(throwing:error)}else{continuation.resume()}}}}
    private func readDatagrams(_ flow:NEAppProxyUDPFlow)async throws->[(Data,Network.NWEndpoint)]{try await withCheckedThrowingContinuation{continuation in flow.readDatagrams{packets,error in if let error{continuation.resume(throwing:error)}else{continuation.resume(returning:packets ?? [])}}}}
    private static func appToNetwork(_ flow:NEAppProxyTCPFlow,socks:SOCKSConnection)async->PumpResult{while !Task.isCancelled{let data:Data;do{data=try await withCheckedThrowingContinuation{(c:CheckedContinuation<Data,Error>) in flow.readData{data,error in if let error{c.resume(throwing:error)}else{c.resume(returning:data ?? Data())}}}}catch{return .applicationEOF("read-error:\(error)")};if data.isEmpty{return .applicationEOF("empty-read")};do{try await socks.send(data)}catch{return .failed("upstream-send:\(error)")}};return .failed("application-pump-cancelled")}
    private static func networkToApp(socks:SOCKSConnection,flow:NEAppProxyTCPFlow)async->PumpResult{while !Task.isCancelled{do{let data=try await socks.receiveSome();try await withCheckedThrowingContinuation{(c:CheckedContinuation<Void,Error>) in flow.write(data){error in if let error{c.resume(throwing:error)}else{c.resume()}}}}catch SOCKSError.closed{return .networkEOF}catch{return .failed("network-pump:\(error)")}};return .failed("network-pump-cancelled")}
	private func appToUDP(_ flow:NEAppProxyUDPFlow,connection:NWConnection,configuration:ProviderConfiguration,dnsResponses:DNSResponseMap)async{while !Task.isCancelled{do{let packets=try await readDatagrams(flow);if packets.isEmpty{return};for(payload,endpoint) in packets{guard let address=Self.address(endpoint)else{continue};let routed=configuration.routedDestination(for:address);if routed != address{await dnsResponses.record(query:payload,original:address,routed:routed)};record(flow:flow,destination:address,routedDestination:routed);var frame=Data([0,0,0]);frame.append(try routed.encoded());frame.append(payload);try await sendDatagram(frame,on:connection)}}catch{return}}}
	private func sendDatagram(_ data:Data,on connection:NWConnection)async throws{try await withCheckedThrowingContinuation{(continuation:CheckedContinuation<Void,Error>) in connection.send(content:data,completion:.contentProcessed{error in if let error{continuation.resume(throwing:error)}else{continuation.resume()}})}}
    private func udpToApp(_ connection:NWConnection,flow:NEAppProxyUDPFlow,dnsResponses:DNSResponseMap)async{while !Task.isCancelled{do{let frame=try await withCheckedThrowingContinuation{(c:CheckedContinuation<Data,Error>) in connection.receiveMessage{data,_,_,error in if let error{c.resume(throwing:error)}else if let data{c.resume(returning:data)}else{c.resume(throwing:SOCKSError.closed)}}};guard frame.count>3,frame[0]==0,frame[1]==0,frame[2]==0 else{continue};var offset=3;let source=try SOCKSAddress.decode(frame,offset:&offset);let payload=Data(frame[offset...]);let responseSource=await dnsResponses.original(for:payload,receivedFrom:source) ?? source;let endpoint=Network.NWEndpoint.hostPort(host:NWEndpoint.Host(responseSource.host),port:NWEndpoint.Port(rawValue:responseSource.port)!);try await flow.writeDatagrams([(payload,endpoint)])}catch{return}}}
}

actor DNSResponseMap {
	private struct Entry { let original: SOCKSAddress; let routed: SOCKSAddress }
	private var entries: [UInt16: [Entry]] = [:]
	private var count = 0

	func record(query: Data, original: SOCKSAddress, routed: SOCKSAddress) {
		guard let identifier=Self.identifier(in:query) else{return}
		if count >= 4096 { entries.removeAll(keepingCapacity:true);count=0 }
		entries[identifier,default:[]].append(Entry(original:original,routed:routed));count += 1
	}

	func original(for response: Data, receivedFrom source: SOCKSAddress) -> SOCKSAddress? {
		guard let identifier=Self.identifier(in:response),var candidates=entries[identifier],let index=candidates.firstIndex(where:{$0.routed == source}) else{return nil}
		let original=candidates.remove(at:index).original;count -= 1
		if candidates.isEmpty{entries.removeValue(forKey:identifier)}else{entries[identifier]=candidates}
		return original
	}

	private static func identifier(in message: Data) -> UInt16? {
		guard message.count >= 2 else{return nil}
		return UInt16(message[message.startIndex]) << 8 | UInt16(message[message.index(after:message.startIndex)])
	}
}
