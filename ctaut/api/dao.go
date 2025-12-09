package api

import (
	"github.com/abesuite/abec/ctaut/dao"
	"github.com/abesuite/abec/ctaut/extscript"
	"github.com/abesuite/abec/ctaut/script"
)

type HostOutPoint = dao.HostOutPoint
type AutIssuer = dao.AutIssuer

type AutId = dao.AutId

type AutPrivacyType = dao.AutPrivacyType

const (
	PrivacyTypeUnlimited     = dao.PrivacyTypeUnlimited
	PrivacyTypeLimitedPublic = dao.PrivacyTypeLimitedPublic
	PrivacyTypeLimitedHidden = dao.PrivacyTypeLimitedHidden
)

type AutScriptType = script.AutScriptType

type AutScript = script.AutScript
type RegistrationScript = script.RegistrationScript
type ReRegistrationScript = script.ReRegistrationScript
type MintScript = script.MintScript
type TransferScript = script.TransferScript
type BurnScript = script.BurnScript

type ExtAutScript = extscript.ExtAutScript

type AutMetadata = script.AutMetadata

func NewAutIssuerFromCoinAddress(coinAddress []byte) *AutIssuer {
	return dao.NewAutIssuerFromCoinAddress(coinAddress)
}
