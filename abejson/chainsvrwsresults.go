package abejson

// SessionResult models the data from the session command.
type SessionResult struct {
	SessionID uint64 `json:"sessionid"`
}

// RescannedBlock contains the hash and all discovered transactions of a single
// rescanned block.
//
// NOTE: This is a btcsuite extension ported from
// github.com/decred/dcrd/dcrjson.
type RescannedBlock struct {
	Hash         string   `json:"hash"`
	Transactions []string `json:"transactions"`
}
