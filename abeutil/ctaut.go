package abeutil

import (
	"github.com/abesuite/abec/ctaut"
	"github.com/abesuite/abec/wire"
)

type AutScript struct {
	HostTx *wire.MsgTxAbe
	Script *ctaut.EnhancedAutScript
}
