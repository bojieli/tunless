package dnswire

import "testing"

func TestAnswersQuery(t *testing.T) {
	query := make([]byte, headerSize)
	query[0], query[1] = 0x12, 0x34
	response := func(id0, id1, flags byte) []byte {
		reply := make([]byte, headerSize)
		reply[0], reply[1], reply[2] = id0, id1, flags
		return reply
	}
	tests := []struct {
		name  string
		query []byte
		reply []byte
		want  bool
	}{
		{"matching response", query, response(0x12, 0x34, 0x80), true},
		{"another transaction", query, response(0x12, 0x35, 0x80), false},
		{"echoed query", query, response(0x12, 0x34, 0x00), false},
		{"truncated reply", query, []byte{0x12, 0x34}, false},
		{"query without a header", []byte{0x12}, response(0x99, 0x99, 0x80), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AnswersQuery(tt.query, tt.reply); got != tt.want {
				t.Fatalf("AnswersQuery = %v, want %v", got, tt.want)
			}
		})
	}
}
