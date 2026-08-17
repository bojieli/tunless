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

	private static func receive(_ connection:NWConnection,count:Int)async throws->Data{try await withCheckedThrowingContinuation{continuation in connection.receive(minimumIncompleteLength:count,maximumLength:count){data,_,_,error in if let error{continuation.resume(throwing:error)}else if let data,data.count==count{continuation.resume(returning:data)}else{continuation.resume(throwing:SOCKSError.closed)}}}}
	private static func send(_ connection:NWConnection,_ data:Data)async throws{try await withCheckedThrowingContinuation{(continuation:CheckedContinuation<Void,Error>) in connection.send(content:data,completion:.contentProcessed{error in if let error{continuation.resume(throwing:error)}else{continuation.resume()}})}}
}

final class CaptureFilterTests:XCTestCase {
	func testExclusionsPrecedeInclusions(){let config=ProviderConfiguration(upstreamHost:"127.0.0.1",upstreamPort:7890,includeProcesses:["com.example.*"],excludeProcesses:["*.helper"],includeDestinations:["203.0.113.0/24"],excludeDestinations:["203.0.113.8/32"]);XCTAssertTrue(config.captures(host:"203.0.113.7",signingIdentifier:"com.example.browser"));XCTAssertFalse(config.captures(host:"203.0.113.8",signingIdentifier:"com.example.browser"));XCTAssertFalse(config.captures(host:"203.0.113.7",signingIdentifier:"com.example.helper"));XCTAssertFalse(config.captures(host:"198.51.100.1",signingIdentifier:"com.example.browser"))}
}
