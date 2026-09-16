package wire

import "sync"

// MessageRequests tracks responses expected from one peer. Its methods are safe
// for concurrent use by the peer's input and output handlers. The zero value is
// ready to use.
type MessageRequests struct {
	mu      sync.Mutex
	pending map[string]int
}

// Add records a request before it is written to the connection, so even an
// immediate response can be accepted.
func (r *MessageRequests) Add(msg Message) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		r.pending = make(map[string]int)
	}
	switch msg := msg.(type) {
	case *MsgGetData:
		for _, iv := range msg.InvList {
			r.pending[iv.Type.String()]++
		}
	case *MsgGetHeaders, *MsgNeedSet, *MsgGetBlockTx:
		r.pending[msg.Command()]++
	}
}

// consume checks a message header before its payload is allocated or read.
func (r *MessageRequests) consume(command string) error {
	if r == nil {
		return nil
	}
	var keys []string
	switch command {
	case CmdHeaders:
		keys = []string{CmdGetHeaders}
	case CmdBlock:
		keys = []string{InvTypeBlock.String(), InvTypeWitnessBlock.String()}
	case CmdTx:
		keys = []string{InvTypeWitnessTx.String(), InvTypeTx.String()}
	case CmdPrunedBlock:
		keys = []string{InvTypePrunedBlock.String()}
	case CmdBlockTx:
		keys = []string{CmdGetBlockTx}
	case CmdNeedSetResult:
		keys = []string{CmdNeedSet}
	default:
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, key := range keys {
		if r.pending[key] > 0 {
			r.pending[key]--
			return nil
		}
	}
	return messageError("ReadMessage", "unexpected message "+command)
}

// notFound consumes the alternative response to a getdata request. Do not
// create negative credits for unsolicited or repeated notfound entries.
func (r *MessageRequests) notFound(msg *MsgNotFound) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, iv := range msg.InvList {
		key := iv.Type.String()
		if r.pending[key] > 0 {
			r.pending[key]--
		}
	}
}
