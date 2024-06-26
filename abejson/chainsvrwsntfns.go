// NOTE: This file is intended to house the RPC websocket notifications that are
// supported by a chain server.

package abejson

const (
	// BlockConnectedNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a block has been connected.
	//
	// Deprecated: Use FilteredBlockConnectedNtfnMethod instead.
	BlockConnectedNtfnMethod    = "blockconnected"
	BlockAbeConnectedNtfnMethod = "blockabeconnected"

	// BlockDisconnectedNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a block has been
	// disconnected.
	//
	// Deprecated: Use FilteredBlockDisconnectedNtfnMethod instead.
	BlockDisconnectedNtfnMethod    = "blockdisconnected"
	BlockAbeDisconnectedNtfnMethod = "blockabedisconnected"

	// FilteredBlockConnectedNtfnMethod is the new method used for
	// notifications from the chain server that a block has been connected.
	FilteredBlockConnectedNtfnMethod = "filteredblockconnected"

	// FilteredBlockDisconnectedNtfnMethod is the new method used for
	// notifications from the chain server that a block has been
	// disconnected.
	FilteredBlockDisconnectedNtfnMethod = "filteredblockdisconnected"

	// RecvTxNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a transaction which pays to
	// a registered address has been processed.
	//
	// Deprecated: Use RelevantTxAcceptedNtfnMethod and
	// FilteredBlockConnectedNtfnMethod instead.
	RecvTxNtfnMethod = "recvtx"

	// RedeemingTxNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a transaction which spends a
	// registered outpoint has been processed.
	//
	// Deprecated: Use RelevantTxAcceptedNtfnMethod and
	// FilteredBlockConnectedNtfnMethod instead.
	RedeemingTxNtfnMethod = "redeemingtx"

	// RescanFinishedNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a legacy, deprecated rescan
	// operation has finished.
	//
	// Deprecated: Not used with rescanblocks command.
	RescanFinishedNtfnMethod = "rescanfinished"

	// RescanProgressNtfnMethod is the legacy, deprecated method used for
	// notifications from the chain server that a legacy, deprecated rescan
	// operation this is underway has made progress.
	//
	// Deprecated: Not used with rescanblocks command.
	RescanProgressNtfnMethod = "rescanprogress"

	// TxAcceptedNtfnMethod is the method used for notifications from the
	// chain server that a transaction has been accepted into the mempool.
	TxAcceptedNtfnMethod = "txaccepted"
	TxRollbackNtfnMethod = "txrollback"
	TxInvalidNtfnMethod  = "txinvalid"

	// TxAcceptedVerboseNtfnMethod is the method used for notifications from
	// the chain server that a transaction has been accepted into the
	// mempool.  This differs from TxAcceptedNtfnMethod in that it provides
	// more details in the notification.
	TxAcceptedVerboseNtfnMethod = "txacceptedverbose"

	// RelevantTxAcceptedNtfnMethod is the new method used for notifications
	// from the chain server that inform a client that a transaction that
	// matches the loaded filter was accepted by the mempool.
	RelevantTxAcceptedNtfnMethod = "relevanttxaccepted"
)

// BlockConnectedNtfn defines the blockconnected JSON-RPC notification.
//
// Deprecated: Use FilteredBlockConnectedNtfn instead.
type BlockConnectedNtfn struct {
	Hash   string
	Height int32
	Time   int64
}
type BlockAbeConnectedNtfn struct {
	Hash   string
	Height int32
	Time   int64
}

// NewBlockConnectedNtfn returns a new instance which can be used to issue a
// blockconnected JSON-RPC notification.
//
// Deprecated: Use NewFilteredBlockConnectedNtfn instead.
func NewBlockConnectedNtfn(hash string, height int32, time int64) *BlockConnectedNtfn {
	return &BlockConnectedNtfn{
		Hash:   hash,
		Height: height,
		Time:   time,
	}
}
func NewBlockAbeConnectedNtfn(hash string, height int32, time int64) *BlockAbeConnectedNtfn {
	return &BlockAbeConnectedNtfn{
		Hash:   hash,
		Height: height,
		Time:   time,
	}
}

// BlockDisconnectedNtfn defines the blockdisconnected JSON-RPC notification.
//
// Deprecated: Use FilteredBlockDisconnectedNtfn instead.
type BlockDisconnectedNtfn struct {
	Hash   string
	Height int32
	Time   int64
}
type BlockAbeDisconnectedNtfn struct {
	Hash   string
	Height int32
	Time   int64
}

// NewBlockDisconnectedNtfn returns a new instance which can be used to issue a
// blockdisconnected JSON-RPC notification.
//
// Deprecated: Use NewFilteredBlockDisconnectedNtfn instead.
func NewBlockDisconnectedNtfn(hash string, height int32, time int64) *BlockDisconnectedNtfn {
	return &BlockDisconnectedNtfn{
		Hash:   hash,
		Height: height,
		Time:   time,
	}
}
func NewBlockAbeDisconnectedNtfn(hash string, height int32, time int64) *BlockAbeDisconnectedNtfn {
	return &BlockAbeDisconnectedNtfn{
		Hash:   hash,
		Height: height,
		Time:   time,
	}
}

// FilteredBlockConnectedNtfn defines the filteredblockconnected JSON-RPC
// notification.
type FilteredBlockConnectedNtfn struct {
	Height        int32
	Header        string
	SubscribedTxs []string
}

// NewFilteredBlockConnectedNtfn returns a new instance which can be used to
// issue a filteredblockconnected JSON-RPC notification.
func NewFilteredBlockConnectedNtfn(height int32, header string, subscribedTxs []string) *FilteredBlockConnectedNtfn {
	return &FilteredBlockConnectedNtfn{
		Height:        height,
		Header:        header,
		SubscribedTxs: subscribedTxs,
	}
}

// FilteredBlockDisconnectedNtfn defines the filteredblockdisconnected JSON-RPC
// notification.
type FilteredBlockDisconnectedNtfn struct {
	Height int32
	Header string
}

// NewFilteredBlockDisconnectedNtfn returns a new instance which can be used to
// issue a filteredblockdisconnected JSON-RPC notification.
func NewFilteredBlockDisconnectedNtfn(height int32, header string) *FilteredBlockDisconnectedNtfn {
	return &FilteredBlockDisconnectedNtfn{
		Height: height,
		Header: header,
	}
}

// BlockDetails describes details of a tx in a block.
type BlockDetails struct {
	Height int32  `json:"height"`
	Hash   string `json:"hash"`
	Index  int    `json:"index"`
	Time   int64  `json:"time"`
}

// RecvTxNtfn defines the recvtx JSON-RPC notification.
//
// Deprecated: Use RelevantTxAcceptedNtfn and FilteredBlockConnectedNtfn
// instead.
type RecvTxNtfn struct {
	HexTx string
	Block *BlockDetails
}

// NewRecvTxNtfn returns a new instance which can be used to issue a recvtx
// JSON-RPC notification.
//
// Deprecated: Use NewRelevantTxAcceptedNtfn and
// NewFilteredBlockConnectedNtfn instead.
func NewRecvTxNtfn(hexTx string, block *BlockDetails) *RecvTxNtfn {
	return &RecvTxNtfn{
		HexTx: hexTx,
		Block: block,
	}
}

// RedeemingTxNtfn defines the redeemingtx JSON-RPC notification.
//
// Deprecated: Use RelevantTxAcceptedNtfn and FilteredBlockConnectedNtfn
// instead.
type RedeemingTxNtfn struct {
	HexTx string
	Block *BlockDetails
}

// NewRedeemingTxNtfn returns a new instance which can be used to issue a
// redeemingtx JSON-RPC notification.
//
// Deprecated: Use NewRelevantTxAcceptedNtfn and
// NewFilteredBlockConnectedNtfn instead.
func NewRedeemingTxNtfn(hexTx string, block *BlockDetails) *RedeemingTxNtfn {
	return &RedeemingTxNtfn{
		HexTx: hexTx,
		Block: block,
	}
}

func NewRedeemingTxNtfnAbe(hexTx string, block *BlockDetails) *RedeemingTxNtfn {
	return &RedeemingTxNtfn{
		HexTx: hexTx,
		Block: block,
	}
}

// RescanFinishedNtfn defines the rescanfinished JSON-RPC notification.
//
// Deprecated: Not used with rescanblocks command.
//	todo(ABE): handleRescan seems not work well. ABE does not supprt it at this moment.
//type RescanFinishedNtfn struct {
//	Hash   string
//	Height int32
//	Time   int64
//}

// NewRescanFinishedNtfn returns a new instance which can be used to issue a
// rescanfinished JSON-RPC notification.
//
// Deprecated: Not used with rescanblocks command.
//	todo(ABE): handleRescan seems not work well. ABE does not supprt it at this moment.
//func NewRescanFinishedNtfn(hash string, height int32, time int64) *RescanFinishedNtfn {
//	return &RescanFinishedNtfn{
//		Hash:   hash,
//		Height: height,
//		Time:   time,
//	}
//}

// RescanProgressNtfn defines the rescanprogress JSON-RPC notification.
//
// Deprecated: Not used with rescanblocks command.
type RescanProgressNtfn struct {
	Hash   string
	Height int32
	Time   int64
}

// NewRescanProgressNtfn returns a new instance which can be used to issue a
// rescanprogress JSON-RPC notification.
//
// Deprecated: Not used with rescanblocks command.
func NewRescanProgressNtfn(hash string, height int32, time int64) *RescanProgressNtfn {
	return &RescanProgressNtfn{
		Hash:   hash,
		Height: height,
		Time:   time,
	}
}

// TxAcceptedNtfn defines the txaccepted JSON-RPC notification.
type TxAcceptedNtfn struct {
	TxID   string
	Height int32
}

// NewTxAcceptedNtfn returns a new instance which can be used to issue a
// txaccepted JSON-RPC notification.
func NewTxAcceptedNtfn(txHash string, height int32) *TxAcceptedNtfn {
	return &TxAcceptedNtfn{
		TxID:   txHash,
		Height: height,
	}
}

type TxRollbackNtfn struct {
	TxID   string
	Height int32
}

func NewTxRollbackNtfn(txHash string, height int32) *TxRollbackNtfn {
	return &TxRollbackNtfn{
		TxID:   txHash,
		Height: height,
	}
}

type TxInvalidNtfn struct {
	TxID   string
	Height int32
}

func NewTxInvalidNtfn(txHash string, height int32) *TxInvalidNtfn {
	return &TxInvalidNtfn{
		TxID:   txHash,
		Height: height,
	}
}

// TxAcceptedVerboseNtfn defines the txacceptedverbose JSON-RPC notification.
//
//	todo(ABE):
type TxAcceptedVerboseNtfn struct {
	RawTx TxRawResult
}

type TxAcceptedVerboseNtfnAbe struct {
	RawTx TxRawResultAbe
}

// NewTxAcceptedVerboseNtfn returns a new instance which can be used to issue a
// txacceptedverbose JSON-RPC notification.
//
//	todo(ABE):
func NewTxAcceptedVerboseNtfn(rawTx TxRawResult) *TxAcceptedVerboseNtfn {
	return &TxAcceptedVerboseNtfn{
		RawTx: rawTx,
	}
}

func NewTxAcceptedVerboseNtfnAbe(rawTx TxRawResultAbe) *TxAcceptedVerboseNtfnAbe {
	return &TxAcceptedVerboseNtfnAbe{
		RawTx: rawTx,
	}
}

// RelevantTxAcceptedNtfn defines the parameters to the relevanttxaccepted
// JSON-RPC notification.
type RelevantTxAcceptedNtfn struct {
	Transaction string `json:"transaction"`
}

// NewRelevantTxAcceptedNtfn returns a new instance which can be used to issue a
// relevantxaccepted JSON-RPC notification.
func NewRelevantTxAcceptedNtfn(txHex string) *RelevantTxAcceptedNtfn {
	return &RelevantTxAcceptedNtfn{Transaction: txHex}
}

func init() {
	// The commands in this file are only usable by websockets and are
	// notifications.
	flags := UFWebsocketOnly | UFNotification

	MustRegisterCmd(BlockConnectedNtfnMethod, (*BlockConnectedNtfn)(nil), flags)
	MustRegisterCmd(BlockAbeConnectedNtfnMethod, (*BlockAbeConnectedNtfn)(nil), flags)
	MustRegisterCmd(BlockDisconnectedNtfnMethod, (*BlockDisconnectedNtfn)(nil), flags)
	MustRegisterCmd(BlockAbeDisconnectedNtfnMethod, (*BlockAbeDisconnectedNtfn)(nil), flags)
	MustRegisterCmd(FilteredBlockConnectedNtfnMethod, (*FilteredBlockConnectedNtfn)(nil), flags)
	MustRegisterCmd(FilteredBlockDisconnectedNtfnMethod, (*FilteredBlockDisconnectedNtfn)(nil), flags)
	MustRegisterCmd(RecvTxNtfnMethod, (*RecvTxNtfn)(nil), flags)
	MustRegisterCmd(RedeemingTxNtfnMethod, (*RedeemingTxNtfn)(nil), flags)
	//	todo(ABE): handleRescan seems not work well. ABE does not supprt it at this moment.
	//MustRegisterCmd(RescanFinishedNtfnMethod, (*RescanFinishedNtfn)(nil), flags)
	//MustRegisterCmd(RescanProgressNtfnMethod, (*RescanProgressNtfn)(nil), flags)
	MustRegisterCmd(TxAcceptedNtfnMethod, (*TxAcceptedNtfn)(nil), flags)
	MustRegisterCmd(TxRollbackNtfnMethod, (*TxRollbackNtfn)(nil), flags)
	MustRegisterCmd(TxInvalidNtfnMethod, (*TxInvalidNtfn)(nil), flags)
	MustRegisterCmd(TxAcceptedVerboseNtfnMethod, (*TxAcceptedVerboseNtfn)(nil), flags)
	MustRegisterCmd(RelevantTxAcceptedNtfnMethod, (*RelevantTxAcceptedNtfn)(nil), flags)
}
