package api

import (
	"github.com/abesuite/abec/ctaut/rules"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
)

// RuleCheckOnHostTxo would check the following rule on HostTxo:
// 1. the privacy level MUST be abecryptoxkey.PrivacyLevelPSEUDONYMCT, note that this means the value in Abelian-Txo is public
// 2. the value must be 1 Neutrino
//
// If the checks are passed, the coinAddress will be returned.
func RuleCheckOnHostTxo(txOut *wire.TxOutAbe) ([]byte, error) {
	return rules.RuleCheckOnHostTxo(txOut)
}

// RuleCheckOnAutTxInputVersion checks whether the inputAutTxo's version matches the autScriptVersion.
func RuleCheckOnAutTxInputVersion(autScriptVersion uint32, inputAutTxo *ctautwire.AutTxo) error {
	return rules.RuleCheckOnAutTxInputVersion(autScriptVersion, inputAutTxo)
}
