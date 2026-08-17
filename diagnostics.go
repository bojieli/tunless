package tunless

type MapDiagnostics struct {
	Entries    uint64 `json:"entries"`
	MaxEntries uint32 `json:"max_entries"`
	Memlock    uint64 `json:"memlock_bytes,omitempty"`
	Error      string `json:"error,omitempty"`
}

type BackendDiagnostics struct {
	Name         string                    `json:"name"`
	Started      bool                      `json:"started"`
	Listeners    int                       `json:"listeners"`
	UDPSockets   int                       `json:"udp_sockets"`
	Links        int                       `json:"links"`
	Associations int                       `json:"udp_associations"`
	Maps         map[string]MapDiagnostics `json:"maps,omitempty"`
}

type DiagnosticsProvider interface {
	Diagnostics() BackendDiagnostics
}
