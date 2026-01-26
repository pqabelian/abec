package abecryptoxparamctx

import (
	"fmt"

	"github.com/pqabelian/abec/abecryptox/abecryptoxparam"
)

// GetCryptoSchemeByAutScriptVersion
// ctx review done 2025.12.21
func GetCryptoSchemeByAutScriptVersion(autScriptVersion uint32) (abecryptoxparam.CryptoScheme, error) {
	//	todo: for each AutScriptVersion, there is a corresponding CryptoScheme
	// AutScriptVersion --> TxVersion --> CryptoScheme
	switch autScriptVersion {
	case 1: // AutScriptVersion_1
		return abecryptoxparam.CryptoSchemePQRingCTX, nil
	default:
		return 0, fmt.Errorf("GetCryptoSchemeByAutScriptVersion: Unsupported AutScriptVersion")
	}
}

// ctx review done 2025.12.21
