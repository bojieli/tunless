// Package dnswire holds the small checks that both DNS forwarding paths apply
// to a datagram before treating it as an answer.
package dnswire

// headerSize is the fixed DNS message header: ID, flags, and four counts.
const headerSize = 12

// AnswersQuery reports whether reply can be the answer to query.
//
// A UDP exchange is one socket, one outstanding question, and whatever arrives
// first. Without this check the first datagram to reach the socket wins, and a
// datagram is a cheap thing to send for anyone who can guess an ephemeral
// port: forging one does not poison anything — the application checks the ID
// itself — but it does consume the exchange, and the real answer arriving a
// moment later finds the socket closed. Matching the transaction ID and the
// response bit means a forged datagram is ignored while the exchange stays
// open for the answer.
//
// A query too short to carry a header is passed through rather than judged.
// There is nothing to match it against, and inventing a verdict would only
// hide the caller's own bug.
func AnswersQuery(query, reply []byte) bool {
	if len(query) < headerSize {
		return true
	}
	if len(reply) < headerSize {
		return false
	}
	// Byte 2 carries QR in its high bit. A message that is not marked as a
	// response is not one, whatever else it says.
	return reply[0] == query[0] && reply[1] == query[1] && reply[2]&0x80 != 0
}
