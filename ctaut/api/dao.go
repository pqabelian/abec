package api

import (
	"github.com/abesuite/abec/ctaut/extscript"
	"github.com/abesuite/abec/ctaut/script"
)

// All CT-AUT Script must start with the following specified prefix.
// Any that starts with this prefix but does not have valid script content will be rejected.
// Use a constant string to avoid unconscious modifications
const commonPrefix = "AUTSCRIPT"

type HostOutPoint = script.HostOutPoint
type AutIssuer = script.AutIssuer

func NewAutIssuer(coinAddress []byte) *AutIssuer {
	return script.NewAutIssuer(coinAddress)
}

type AutId = script.AutId

type AutScript = script.AutScript
type RegistrationScript = script.RegistrationScript
type ReRegistrationScript = script.ReRegistrationScript
type MintScript = script.MintScript
type TransferScript = script.TransferScript
type BurnScript = script.BurnScript

type ExtAutScript = extscript.ExtAutScript

type AutMetadata = script.AutMetadata
