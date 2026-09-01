import XCTest
import Network
@testable import TunlessExtension

final class SOCKS5Tests:XCTestCase {
    func testAddressRoundTrip()throws{for value in [SOCKSAddress(host:"1.2.3.4",port:443),SOCKSAddress(host:"::1",port:53),SOCKSAddress(host:"example.com",port:8443)]{let encoded=try value.encoded();var offset=0;XCTAssertEqual(try SOCKSAddress.decode(encoded,offset:&offset),value);XCTAssertEqual(offset,encoded.count)}}

	func testAuthenticatedConnectAndRelay()async throws{
		let listener=try NWListener(using:.tcp,on:.any);let ready=expectation(description:"listener ready");let served=expectation(description:"SOCKS request served")
		listener.stateUpdateHandler={state in if case .ready=state{ready.fulfill()}}
		listener.newConnectionHandler={connection in connection.start(queue:.global());Task{do{let greeting=try await Self.receive(connection,count:3);XCTAssertEqual(greeting,Data([5,1,2]));try await Self.send(connection,Data([5,2]));let authHead=try await Self.receive(connection,count:2);let user=try await Self.receive(connection,count:Int(authHead[1]));let passSize=try await Self.receive(connection,count:1);let pass=try await Self.receive(connection,count:Int(passSize[0]));XCTAssertEqual(String(decoding:user,as:UTF8.self),"identity");XCTAssertEqual(String(decoding:pass,as:UTF8.self),"secret");try await Self.send(connection,Data([1,0]));let request=try await Self.receive(connection,count:18);XCTAssertEqual(request.prefix(5),Data([5,1,0,3,11]));XCTAssertEqual(String(decoding:request[5..<16],as:UTF8.self),"example.com");try await Self.send(connection,Data([5,0,0,1,127,0,0,1,31,144]));let ping=try await Self.receive(connection,count:4);XCTAssertEqual(ping,Data("ping".utf8));try await Self.send(connection,Data("pong".utf8));do{_ = try await Self.receive(connection,count:1);XCTFail("expected client half-close")}catch{};served.fulfill()}catch{XCTFail("mock SOCKS server: \(error)");served.fulfill()}}}
		listener.start(queue:.global());await fulfillment(of:[ready],timeout:2);guard let port=listener.port else{XCTFail("listener has no port");return}
		let configuration=ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:port.rawValue,username:"identity",password:"secret");let client=SOCKSConnection(configuration:configuration);let bound=try await client.open(configuration:configuration,command:1,destination:SOCKSAddress(host:"example.com",port:443));XCTAssertEqual(bound,SOCKSAddress(host:"127.0.0.1",port:8080));try await client.send(Data("ping".utf8));try await client.finishSending();let pong=try await client.receiveSome();XCTAssertEqual(pong,Data("pong".utf8));await fulfillment(of:[served],timeout:2);await client.cancel();listener.cancel()
	}

	func testRejectsNoAuthWhenCredentialsWereRequired()async throws{
		let listener=try NWListener(using:.tcp,on:.any);let ready=expectation(description:"listener ready");let served=expectation(description:"greeting served")
		listener.stateUpdateHandler={state in if case .ready=state{ready.fulfill()}}
		listener.newConnectionHandler={connection in connection.start(queue:.global());Task{do{let greeting=try await Self.receive(connection,count:3);XCTAssertEqual(greeting,Data([5,1,2]));try await Self.send(connection,Data([5,0]));served.fulfill()}catch{XCTFail("mock SOCKS server: \(error)");served.fulfill()}}}
		listener.start(queue:.global());await fulfillment(of:[ready],timeout:2);guard let port=listener.port else{XCTFail("listener has no port");return}
		let configuration=ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:port.rawValue,username:"identity",password:"secret");let client=SOCKSConnection(configuration:configuration)
		do{_ = try await client.open(configuration:configuration,command:1,destination:SOCKSAddress(host:"example.com",port:443));XCTFail("accepted an authentication method that was not offered")}catch{}
		await fulfillment(of:[served],timeout:2);await client.cancel();listener.cancel()
	}

	func testReceivesResponseSentAfterClientHalfClose()async throws{
		let listener=try NWListener(using:.tcp,on:.any);let ready=expectation(description:"listener ready");let served=expectation(description:"response after FIN served")
		listener.stateUpdateHandler={state in if case .ready=state{ready.fulfill()}}
		listener.newConnectionHandler={connection in connection.start(queue:.global());Task{do{_ = try await Self.receive(connection,count:3);try await Self.send(connection,Data([5,0]));_ = try await Self.receive(connection,count:10);try await Self.send(connection,Data([5,0,0,1,127,0,0,1,0,80]));let ping=try await Self.receive(connection,count:4);XCTAssertEqual(ping,Data("ping".utf8));do{_ = try await Self.receive(connection,count:1);XCTFail("expected client half-close")}catch{};try await Task.sleep(nanoseconds:1_000_000_000);try await Self.send(connection,Data("pong".utf8));served.fulfill()}catch{XCTFail("mock SOCKS server: \(error)");served.fulfill()}}}
		listener.start(queue:.global());await fulfillment(of:[ready],timeout:2);guard let port=listener.port else{XCTFail("listener has no port");return}
		let configuration=ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:port.rawValue);let client=SOCKSConnection(configuration:configuration);_ = try await client.open(configuration:configuration,command:1,destination:SOCKSAddress(host:"1.2.3.4",port:80));let response=Task{try await client.receiveSome()};await Task.yield();try await client.send(Data("ping".utf8));try await client.finishSending();let pong=try await response.value;XCTAssertEqual(pong,Data("pong".utf8));await fulfillment(of:[served],timeout:3);await client.cancel();listener.cancel()
	}

	func testUDPAssociateAndDomainReply()async throws{
		let listener=try NWListener(using:.tcp,on:.any);let ready=expectation(description:"listener ready");let served=expectation(description:"UDP associate served")
		listener.stateUpdateHandler={state in if case .ready=state{ready.fulfill()}}
		listener.newConnectionHandler={connection in connection.start(queue:.global());Task{do{let greeting=try await Self.receive(connection,count:3);XCTAssertEqual(greeting,Data([5,1,0]));try await Self.send(connection,Data([5,0]));let request=try await Self.receive(connection,count:10);XCTAssertEqual(request,Data([5,3,0,1,0,0,0,0,0,0]));var reply=Data([5,0,0,3,10]);reply.append(Data("relay.test".utf8));reply.append(contentsOf:[0x12,0x34]);try await Self.send(connection,reply);served.fulfill()}catch{XCTFail("mock SOCKS UDP server: \(error)");served.fulfill()}}}
		listener.start(queue:.global());await fulfillment(of:[ready],timeout:2);guard let port=listener.port else{XCTFail("listener has no port");return}
		let configuration=ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:port.rawValue);let client=SOCKSConnection(configuration:configuration);let relay=try await client.open(configuration:configuration,command:3,destination:SOCKSAddress(host:"0.0.0.0",port:0));XCTAssertEqual(relay,SOCKSAddress(host:"relay.test",port:0x1234));await fulfillment(of:[served],timeout:2);await client.cancel();listener.cancel()
	}

	func testRejectsAuthenticationThatWasNotOffered()async throws{
		let listener=try NWListener(using:.tcp,on:.any);let ready=expectation(description:"listener ready");let served=expectation(description:"greeting served")
		listener.stateUpdateHandler={state in if case .ready=state{ready.fulfill()}}
		listener.newConnectionHandler={connection in connection.start(queue:.global());Task{do{let greeting=try await Self.receive(connection,count:3);XCTAssertEqual(greeting,Data([5,1,0]));try await Self.send(connection,Data([5,2]));served.fulfill()}catch{XCTFail("mock SOCKS server: \(error)");served.fulfill()}}}
		listener.start(queue:.global());await fulfillment(of:[ready],timeout:2);guard let port=listener.port else{XCTFail("listener has no port");return}
		let configuration=ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:port.rawValue);let client=SOCKSConnection(configuration:configuration)
		do{_ = try await client.open(configuration:configuration,command:1,destination:SOCKSAddress(host:"example.com",port:443));XCTFail("accepted username/password without offering it")}catch{}
		await fulfillment(of:[served],timeout:2);await client.cancel();listener.cancel()
	}

	func testHandshakeTimeoutCancelsPendingCallbacks()async throws{
		let listener=try NWListener(using:.tcp,on:.any);let ready=expectation(description:"listener ready");let accepted=expectation(description:"connection accepted")
		listener.stateUpdateHandler={state in if case .ready=state{ready.fulfill()}}
		listener.newConnectionHandler={connection in connection.start(queue:.global());accepted.fulfill()}
		listener.start(queue:.global());await fulfillment(of:[ready],timeout:2);guard let port=listener.port else{XCTFail("listener has no port");return}
		let configuration=ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:port.rawValue);let client=SOCKSConnection(configuration:configuration);let started=Date()
		do{_ = try await client.open(configuration:configuration,command:1,destination:SOCKSAddress(host:"1.2.3.4",port:443),timeoutSeconds:0.02);XCTFail("stalled handshake did not time out")}catch{}
		XCTAssertLessThan(Date().timeIntervalSince(started),1);await fulfillment(of:[accepted],timeout:2);await client.cancel();listener.cancel()
	}

	func testAsyncResultGateHandlesCancellationBeforeInstall()async{
		let gate=AsyncResultGate<Void>();gate.resume(with:.failure(CancellationError()))
		do{try await withCheckedThrowingContinuation{(continuation:CheckedContinuation<Void,Error>) in _=gate.install(continuation)};XCTFail("gate lost cancellation")}catch is CancellationError{}catch{XCTFail("unexpected gate error: \(error)")}
	}

	private static func receive(_ connection:NWConnection,count:Int)async throws->Data{try await withCheckedThrowingContinuation{continuation in connection.receive(minimumIncompleteLength:count,maximumLength:count){data,_,_,error in if let error{continuation.resume(throwing:error)}else if let data,data.count==count{continuation.resume(returning:data)}else{continuation.resume(throwing:SOCKSError.closed)}}}}
	private static func send(_ connection:NWConnection,_ data:Data)async throws{try await withCheckedThrowingContinuation{(continuation:CheckedContinuation<Void,Error>) in connection.send(content:data,completion:.contentProcessed{error in if let error{continuation.resume(throwing:error)}else{continuation.resume()}})}}
}

final class CaptureFilterTests:XCTestCase {
	func testExclusionsPrecedeInclusions(){let config=ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:7890,includeProcesses:["com.example.*"],excludeProcesses:["*.helper"],includeDestinations:["203.0.113.0/24"],excludeDestinations:["203.0.113.8/32"]);XCTAssertTrue(config.captures(host:"203.0.113.7",port:443,signingIdentifier:"com.example.browser"));XCTAssertFalse(config.captures(host:"203.0.113.8",port:443,signingIdentifier:"com.example.browser"));XCTAssertFalse(config.captures(host:"203.0.113.7",port:443,signingIdentifier:"com.example.helper"));XCTAssertFalse(config.captures(host:"198.51.100.1",port:443,signingIdentifier:"com.example.browser"))}
	func testConfigurationValidation(){XCTAssertNoThrow(try ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:7890,dnsHost:"1.1.1.1",dnsPort:53,includeDestinations:["0.0.0.0/0","::/0"]).validated());XCTAssertNoThrow(try ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:7890,dnsHost:"2606:4700:4700::1111",dnsPort:53).validated());XCTAssertThrowsError(try ProviderConfiguration(upstreamHost:"",upstreamPort:7890).validated());XCTAssertThrowsError(try ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:7890,dnsHost:"resolver.example",dnsPort:53).validated());XCTAssertThrowsError(try ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:7890,dnsHost:"1.1.1.1").validated());XCTAssertThrowsError(try ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:7890,includeDestinations:["192.0.2.0/99"]).validated());XCTAssertThrowsError(try ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:7890,username:String(repeating:"x",count:256)).validated())}
	func testDNSRoutingOnlyOverridesPort53(){let config=ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:7890,dnsHost:"1.1.1.1",dnsPort:53);XCTAssertEqual(config.routedDestination(for:SOCKSAddress(host:"223.6.6.6",port:53)),SOCKSAddress(host:"1.1.1.1",port:53));XCTAssertEqual(config.routedDestination(for:SOCKSAddress(host:"223.6.6.6",port:853)),SOCKSAddress(host:"223.6.6.6",port:853))}
	func testNoDNSOverridePreservesOriginalResolver(){let config=ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:7890);let destination=SOCKSAddress(host:"223.6.6.6",port:53);XCTAssertEqual(config.routedDestination(for:destination),destination)}
}

final class DNSResponseMapTests:XCTestCase {
	func testRestoresOriginalResolverEndpointAndIdentifier()async{
		// Pin the draw: the allocator is random, and an unpinned run would match
		// the query's own identifier once every 65,536 executions.
		let map=DNSResponseMap(randomIdentifier:{0x4321});let original=SOCKSAddress(host:"223.6.6.6",port:53);let routed=SOCKSAddress(host:"1.1.1.1",port:53)
		let query=Data([0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0]);let translated=await map.prepare(query:query,original:original,routed:routed)
		XCTAssertEqual(translated.prefix(2),Data([0x43,0x21]))
		var response=translated;response[2]=0x81;response[3]=0x80
		let restored=await map.restore(response:response,receivedFrom:routed)
		let count=await map.outstandingCount();XCTAssertEqual(restored.source,original);XCTAssertEqual(restored.payload.prefix(2),query.prefix(2));XCTAssertEqual(count,0)
	}
	func testConcurrentReusedIdentifiersAreUnambiguous()async{
		let map=DNSResponseMap();let firstOriginal=SOCKSAddress(host:"223.6.6.6",port:53);let secondOriginal=SOCKSAddress(host:"8.8.8.8",port:53);let routed=SOCKSAddress(host:"1.1.1.1",port:53);let query=Data([0xab,0xcd,1,0,0,1,0,0,0,0,0,0])
		let first=await map.prepare(query:query,original:firstOriginal,routed:routed);let second=await map.prepare(query:query,original:secondOriginal,routed:routed);XCTAssertNotEqual(first.prefix(2),second.prefix(2))
		let secondResponse=await map.restore(response:second,receivedFrom:routed);let firstResponse=await map.restore(response:first,receivedFrom:routed);XCTAssertEqual(secondResponse.source,secondOriginal);XCTAssertEqual(firstResponse.source,firstOriginal);XCTAssertEqual(secondResponse.payload.prefix(2),query.prefix(2));XCTAssertEqual(firstResponse.payload.prefix(2),query.prefix(2))
	}
	func testDoesNotRewriteResponseFromAnotherSource()async{
		let map=DNSResponseMap();let original=SOCKSAddress(host:"223.6.6.6",port:53);let routed=SOCKSAddress(host:"1.1.1.1",port:53);let query=Data([0xab,0xcd,1,0,0,1,0,0,0,0,0,0]);let translated=await map.prepare(query:query,original:original,routed:routed)
		let other=await map.restore(response:translated,receivedFrom:SOCKSAddress(host:"8.8.8.8",port:53));let expected=await map.restore(response:translated,receivedFrom:routed);XCTAssertEqual(other.source,SOCKSAddress(host:"8.8.8.8",port:53));XCTAssertEqual(expected.source,original)
	}
	func testFailedSendAbandonsItsTranslationAndLoopGuard()async{
		let guardState=ResolverLoopGuard();let map=DNSResponseMap(randomIdentifier:{0x4321},loopGuard:guardState);let original=SOCKSAddress(host:"223.6.6.6",port:53);let routed=SOCKSAddress(host:"1.1.1.1",port:53);let query=Data([0x12,0x34,1,0,0,1,0,0,0,0,0,0])
		let prepared=await map.prepareForSend(query:query,original:original,routed:routed);XCTAssertTrue(guardState.isRelayedQuery(prepared.payload));await map.abandon(prepared);let count=await map.outstandingCount();XCTAssertEqual(count,0);XCTAssertFalse(guardState.isRelayedQuery(prepared.payload))
	}
	func testCollidingMapsDoNotReleaseEachOthersLoopGuard()async{
		let guardState=ResolverLoopGuard();let first=DNSResponseMap(randomIdentifier:{0x4321},loopGuard:guardState);let second=DNSResponseMap(randomIdentifier:{0x4321},loopGuard:guardState);let original=SOCKSAddress(host:"223.6.6.6",port:53);let routed=SOCKSAddress(host:"1.1.1.1",port:53);let query=Data([0x12,0x34,1,0,0,1,0,0,0,0,0,0])
		let one=await first.prepareForSend(query:query,original:original,routed:routed);let two=await second.prepareForSend(query:query,original:original,routed:routed);XCTAssertTrue(one.canSend);XCTAssertTrue(two.canSend);XCTAssertEqual(guardState.count(),2);await first.abandon(one);XCTAssertTrue(guardState.isRelayedQuery(two.payload));await second.abandon(two);XCTAssertFalse(guardState.isRelayedQuery(two.payload))
	}
	func testASaturatedLoopGuardMakesThePreparedQueryFailClosed()async{
		let guardState=ResolverLoopGuard(maxEntries:1);XCTAssertTrue(guardState.register(0x1111));let map=DNSResponseMap(randomIdentifier:{0x4321},loopGuard:guardState);let original=SOCKSAddress(host:"223.6.6.6",port:53);let routed=SOCKSAddress(host:"1.1.1.1",port:53);let query=Data([0x12,0x34,1,0,0,1,0,0,0,0,0,0])
		let prepared=await map.prepareForSend(query:query,original:original,routed:routed);let count=await map.outstandingCount();XCTAssertFalse(prepared.canSend);XCTAssertEqual(count,0);XCTAssertEqual(guardState.count(),1)
	}
	func testTranslatedIdentifiersAreUnpredictable()async{
		let map=DNSResponseMap();let original=SOCKSAddress(host:"223.6.6.6",port:53);let routed=SOCKSAddress(host:"1.1.1.1",port:53);let query=Data([0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0])
		var seen=Set<UInt16>();var previous:UInt16=0;var consecutive=0;let queries=256
		for index in 0..<queries{
			let translated=await map.prepare(query:query,original:original,routed:routed)
			let identifier=UInt16(translated[translated.startIndex])<<8|UInt16(translated[translated.index(after:translated.startIndex)])
			XCTAssertFalse(seen.contains(identifier),"translated identifier \(identifier) was handed out twice");seen.insert(identifier)
			if index>0,identifier==previous&+1{consecutive+=1};previous=identifier
		}
		// A counter scores queries-1 here. Independent draws land on their
		// predecessor's successor about once in 65,536.
		XCTAssertLessThanOrEqual(consecutive,4,"translated identifiers look sequential")
	}
	func testIdentifierAllocationSurvivesCollidingDraws()async{
		let map=DNSResponseMap(randomIdentifier:{0x2000});let first=SOCKSAddress(host:"223.6.6.6",port:53);let second=SOCKSAddress(host:"8.8.8.8",port:53);let routed=SOCKSAddress(host:"1.1.1.1",port:53)
		let one=await map.prepare(query:Data([0x11,0x11,1,0,0,1,0,0,0,0,0,0]),original:first,routed:routed)
		let two=await map.prepare(query:Data([0x22,0x22,1,0,0,1,0,0,0,0,0,0]),original:second,routed:routed)
		XCTAssertEqual(one.prefix(2),Data([0x20,0x00]));XCTAssertEqual(two.prefix(2),Data([0x20,0x01]))
		let restored=await map.restore(response:two,receivedFrom:routed);XCTAssertEqual(restored.source,second);XCTAssertEqual(restored.payload.prefix(2),Data([0x22,0x22]))
	}
	func testMapIsBoundedAndExpiresEntries()async throws{
		let map=DNSResponseMap(maxEntries:2,ttlSeconds:0.01);let original=SOCKSAddress(host:"223.6.6.6",port:53);let routed=SOCKSAddress(host:"1.1.1.1",port:53)
		for id:UInt8 in 1...3{_ = await map.prepare(query:Data([0,id,1,0,0,1,0,0,0,0,0,0]),original:original,routed:routed)};let bounded=await map.outstandingCount();XCTAssertEqual(bounded,2);try await Task.sleep(nanoseconds:20_000_000);_ = await map.prepare(query:Data([0,4,1,0,0,1,0,0,0,0,0,0]),original:original,routed:routed);let pruned=await map.outstandingCount();XCTAssertEqual(pruned,1)
	}
}

final class InactivityDeadlineTests:XCTestCase {
	func testDeadlineExpires()async{
		let deadline=InactivityDeadline(timeoutSeconds:0.01);let started=Date();let expired=await deadline.waitForExpiry();XCTAssertTrue(expired);XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(started),0.008)
	}
	func testActivityPostponesDeadline()async throws{
		let deadline=InactivityDeadline(timeoutSeconds:0.03);try await Task.sleep(nanoseconds:20_000_000);await deadline.touch();let started=Date();let expired=await deadline.waitForExpiry();XCTAssertTrue(expired);XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(started),0.02)
	}
	func testZeroDisablesTheDeadline()async throws{
		let deadline=InactivityDeadline(timeoutSeconds:0);let waiting=Task{await deadline.waitForExpiry()};try await Task.sleep(nanoseconds:20_000_000);waiting.cancel();let expired=await waiting.value;XCTAssertFalse(expired)
	}
}
