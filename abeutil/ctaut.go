package abeutil

import (
	"github.com/abesuite/abec/ctaut"
	"github.com/abesuite/abec/wire"
)

type CTAUTScript struct {
	HostTx *wire.MsgTxAbe
	Script ctaut.CTAUTScript
}
