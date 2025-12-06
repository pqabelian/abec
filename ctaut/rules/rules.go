package rules

import (
	"encoding/hex"
	"fmt"
	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/ctaut/extscript/auttoken"
	"github.com/abesuite/abec/ctaut/script"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
)

// RuleGetTxVersionFromAutScriptVersion defines a map from AutScriptVersion to host-Txo-Version.
//
// See the design on version in ctaut/wire.
func RuleGetTxVersionFromAutScriptVersion(autScriptVersion uint32) (uint32, error) {
	switch autScriptVersion {
	case ctautwire.AutScriptVersion_1:
		return wire.TxVersion_Height_464000_Aconcagua, nil
	default:
		return 0, fmt.Errorf("RuleGetTxVersionFromAutScriptVersion: unknown autScriptVersion %d", autScriptVersion)
	}
}

// RuleCheckOnHostTxo would check the following rule on HostTxo
// 1. the privacy level MUST be abecryptoxkey.PrivacyLevelPSEUDONYMCT, note that this means the value in Abelian-Txo is public
// 2. the value must be 1 Neutrino
// todo: txHash and outputIndex donot have actual use.
func RuleCheckOnHostTxo(hostOutPoint *script.HostOutPoint, txOut *wire.TxOutAbe) ([]byte, error) {
	privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
	if err != nil {
		return nil, fmt.Errorf("fail to extract the privacy level from transaction %s:%s", hostOutPoint.TxHash, err.Error())
	}
	if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
		return nil, fmt.Errorf("invalid privacy level to %d-th output from transaction %s", hostOutPoint.Index, hostOutPoint.TxHash)
	}

	// todo: the above codes are necessary, since if it is not Pseudonym, the PseudonymTxoCoinParse will return error.
	coinAddress, coinValue, err := abecryptox.PseudonymTxoCoinParse(txOut)
	if err != nil {
		return nil, fmt.Errorf("fail to parse %d-th output as an pseudonym txo from transaction %s", hostOutPoint.Index, hostOutPoint.TxHash)
	}
	if coinValue != 1 {
		return nil, fmt.Errorf("invalid value from %d-th output from transaction %s as AUT coin", hostOutPoint.Index, hostOutPoint.TxHash)
	}

	// remove the start codes, and check coinAddress here; need to add an api abecryptox.GetPrivacyLevelFromCoinAddress(),
	// which does not parse all, to improve efficiency
	return coinAddress, nil
}

func RuleCheckOnAutTxoVersionType(autScriptVersion uint32, autTxo *ctautwire.AutTxo) error {
	autTxoType, err := abecryptox.GetAutTxoType(autTxo)
	if err != nil {
		return fmt.Errorf("fail to get last aut txo type: %v", err)
	}

	err = abecryptox.AutRuleCheckOnAutTxoVersionType(autScriptVersion, autTxoType)
	if err != nil {
		return fmt.Errorf("fail to pass the AutRuleCheckOnTxoVersionType: %v", err)
	}
	return nil
}

// RuleCheckOnIssuerHostClaim checks that
// (1) each claimed issuer has at least one corresponding AutToken, and
// (2) each output AutToken has a corresponding issuer.
func RuleCheckOnIssuerHostClaim(issuers []*script.AutIssuer, outputTokens []*auttoken.AutToken) error {
	claimedIssuersByCoinAddress := make(map[string]*script.AutIssuer, len(issuers))
	for i := 0; i < len(issuers); i++ {
		coinAddressStr := hex.EncodeToString(issuers[i].CoinAddress())
		// ensure no duplicates one
		if _, ok := claimedIssuersByCoinAddress[coinAddressStr]; ok {
			return fmt.Errorf("claimed repeated issuers")
		}
		claimedIssuersByCoinAddress[coinAddressStr] = issuers[i]
	}

	outputTokenCoinAddressesMap := make(map[string]*auttoken.AutToken, len(outputTokens))
	for i := 0; i < len(outputTokens); i++ {
		coinAddressStr := hex.EncodeToString(outputTokens[i].CoinAddress)
		if _, ok := outputTokenCoinAddressesMap[coinAddressStr]; !ok {
			outputTokenCoinAddressesMap[coinAddressStr] = outputTokens[i]
		} else {
			// do nothing
			// allow repeated, does not matter
		}
	}

	// compare with claimed issueTokens
	if len(outputTokenCoinAddressesMap) != len(claimedIssuersByCoinAddress) {
		return fmt.Errorf("claimed mismatched issue token")
	}
	for coinAddressStr, issuer := range claimedIssuersByCoinAddress {
		if _, ok := outputTokenCoinAddressesMap[coinAddressStr]; !ok {
			return fmt.Errorf("claimed issuer (%s) does not appear in output tokens", issuer.String())
		}
		delete(outputTokenCoinAddressesMap, coinAddressStr)
	}
	if len(outputTokenCoinAddressesMap) != 0 {
		return fmt.Errorf(" %d output tokens do not have corresponding issuer", len(outputTokenCoinAddressesMap))
	}
	return nil
}
