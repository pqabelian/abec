package peer

import "github.com/abesuite/abec/wire"

// Data responses are already covered by the server's service reservation.
// Charge retained request/announcement metadata by size, so one-vector invs do
// not each consume the protocol maximum for fifty thousand vectors.
func (p *Peer) reserveQueuedMessage(msg wire.Message) (*wire.PayloadReservation, bool) {
	var size uint64
	switch msg.Command() {
	case wire.CmdTx, wire.CmdBlock, wire.CmdPrunedBlock, wire.CmdBlockTx, wire.CmdNeedSetResult:
		return nil, true
	default:
		size = uint64(msg.MaxPayloadLength(p.ProtocolVersion()))
	}
	switch msg := msg.(type) {
	case *wire.MsgInv:
		size = wire.MaxVarIntPayload + 36*uint64(len(msg.InvList))
	case *wire.MsgGetData:
		size = wire.MaxVarIntPayload + 36*uint64(len(msg.InvList))
	case *wire.MsgNotFound:
		size = wire.MaxVarIntPayload + 36*uint64(len(msg.InvList))
	case *wire.MsgNeedSet:
		size = 32 + wire.MaxVarIntPayload + 32*uint64(len(msg.Hashes))
	case *wire.MsgGetHeaders:
		size = 4 + wire.MaxVarIntPayload + 32 + 32*uint64(len(msg.BlockLocatorHashes))
	case *wire.MsgGetBlocks:
		size = 4 + wire.MaxVarIntPayload + 32 + 32*uint64(len(msg.BlockLocatorHashes))
	}
	return p.cfg.PayloadBudget.TryReserveQueued(size, msg.Command() == wire.CmdNeedSet || msg.Command() == wire.CmdGetBlockTx)
}
