package api

import (
	"github.com/pqabelian/abec/ctaut/dao"
	"github.com/pqabelian/abec/ctaut/extscript"
	"github.com/pqabelian/abec/ctaut/script"
)

type HostOutPoint = dao.HostOutPoint
type AutId = dao.AutId
type AutIssuer = dao.AutIssuer

type AutScriptType = script.AutScriptType
type AutPrivacyType = script.AutPrivacyType

type AutScript = script.AutScript
type RegistrationScript = script.RegistrationScript
type ReRegistrationScript = script.ReRegistrationScript
type MintScript = script.MintScript
type TransferScript = script.TransferScript
type BurnScript = script.BurnScript
type AutMetadata = script.AutMetadata

type ExtAutScript = extscript.ExtAutScript

func NewAutIssuerFromCoinAddress(coinAddress []byte) *AutIssuer {
	return dao.NewAutIssuerFromCoinAddress(coinAddress)
}

// end of codes
