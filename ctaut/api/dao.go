package api

import (
	"github.com/abesuite/abec/ctaut/extscript"
	"github.com/abesuite/abec/ctaut/script"
)

type HostOutPoint = script.HostOutPoint
type AutIssuer = script.AutIssuer

type AutId = script.AutId

type AutScript = script.AutScript
type RegistrationScript = script.RegistrationScript
type ReRegistrationScript = script.ReRegistrationScript
type MintScript = script.MintScript
type TransferScript = script.TransferScript
type BurnScript = script.BurnScript

type ExtAutScript = extscript.ExtAutScript

type AutMetadata = script.AutMetadata

func NewAutIssuer(issuerAddress []byte) *AutIssuer {
	return script.NewAutIssuer(issuerAddress)
}
