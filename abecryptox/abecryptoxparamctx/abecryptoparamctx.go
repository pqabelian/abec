package abecryptoxparamctx

import (
	"fmt"

	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
)

func GetCryptoSchemeByAutScriptVersion(autScriptVersion uint32) (abecryptoxparam.CryptoScheme, error) {
	//	todo: for each version, there is a corresponding CryptoScheme
	switch autScriptVersion {
	case 1: // wire.TxVersion_Height_0
		return abecryptoxparam.CryptoSchemePQRingCTX, nil
	default:
		return 0, fmt.Errorf("GetCryptoSchemeByAutScriptVersion: Unsupported AutScriptVersion")
	}
}
