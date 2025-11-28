package api

import (
	"github.com/abesuite/abec/ctaut/extscript"
	"github.com/abesuite/abec/ctaut/script"
)

// All CT-AUT Script must start with the following specified prefix.
// Any that starts with this prefix but does not have valid script content will be rejected.
// Use a constant string to avoid unconscious modifications
const commonPrefix = "AUTSCRIPT"

type ExtAutScript = extscript.ExtAutScript

type HostOutPoint = script.HostOutPoint

type AutMetadata = script.AutMetadata
type AutScript = script.AutScript
type RegistrationScript = script.RegistrationScript
type ReRegistrationScript = script.ReRegistrationScript
type MintScript = script.MintScript
type TransferScript = script.TransferScript
type BurnScript = script.BurnScript
