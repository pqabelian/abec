package api

import (
	"github.com/abesuite/abec/ctaut/script"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
)

// All CT-AUT Script must start with the following specified prefix.
// Any that starts with this prefix but does not have valid script content will be rejected.
// Use a constant string to avoid unconscious modifications
const commonPrefix = "AUTSCRIPT"

const MaxAmount = script.MaxAmount
const InfiniteExpireHeight = script.InfiniteExpireHeight
const MaxAutValueScriptLength = script.MaxAutValueScriptLength

const MaxAutNameLength = script.MaxAutNameLength
const MaxAutSymbolLength = script.MaxAutSymbolLength
const MaxBaseUnitLength = script.MaxBaseUnitLength
const MaxSubUnitLength = script.MaxSubUnitLength

const (
	AutScriptTypeRegistration   = script.AutScriptTypeRegistration
	AutScriptTypeReRegistration = script.AutScriptTypeReRegistration
	AutScriptTypeMint           = script.AutScriptTypeMint
	AutScriptTypeTransfer       = script.AutScriptTypeTransfer
	AutScriptTypeBurn           = script.AutScriptTypeBurn
)

const (
	AutPrivacyTypeUnlimited     = script.AutPrivacyTypeUnlimited
	AutPrivacyTypeLimitedPublic = script.AutPrivacyTypeLimitedPublic
	AutPrivacyTypeLimitedHidden = script.AutPrivacyTypeLimitedHidden
)

const AutMetadataVersionInitValue = ctautwire.AutMetadataVersionInitValue

// end of codes
