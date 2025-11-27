package script

import (
	"encoding/hex"
	"fmt"
	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/chainhash"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
)

var zeroIdentifier = [AutIdentifierLength]byte{}

func init() {
	for i := 0; i < AutIdentifierLength; i++ {
		zeroIdentifier[i] = 0
	}
}

// CheckHostTxoParasiticity would check the following rule:
// 1. the privacy level MUST be abecryptoxkey.PrivacyLevelPSEUDONYMCT, note that this means the value in txo is public
// 2. the value must be 1 Neutrino
// todo: txHash and outputIndex donot have actual use.
func CheckHostTxoParasiticity(txHash chainhash.Hash, outputIndex uint8, txOut *wire.TxOutAbe) ([]byte, error) {
	privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
	if err != nil {
		return nil, fmt.Errorf("fail to extract the privacy level from transaction %s:%s", txHash, err.Error())
	}
	if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
		return nil, fmt.Errorf("invalid privacy level to %d-th output from transaction %s", outputIndex, txHash)
	}

	// todo: the above codes are necessary, since if it is not Pseudonym, the PseudonymTxoCoinParse will return error.
	coinAddress, coinValue, err := abecryptox.PseudonymTxoCoinParse(txOut)
	if err != nil {
		return nil, fmt.Errorf("fail to parse %d-th output as an pseudonym txo from transaction %s", outputIndex, txHash)
	}
	if coinValue != 1 {
		return nil, fmt.Errorf("invalid value from %d-th output from transaction %s as AUT coin", outputIndex, txHash)
	}

	// remove the start codes, and check coinAddress here; need to add an api abecryptox.GetPrivacyLevelFromCoinAddress(),
	// which does not parse all, to improve efficiency
	return coinAddress, nil
}

// GetGeneratedAutTokens would get the specified host output from the host transaction
// todo(ctaut): add comments to define the rules
func GetGeneratedAutTokens(script AutScript, txHash chainhash.Hash, txOuts []*wire.TxOutAbe) ([]*AutToken, error) {
	numCTAUTTokens := script.NumGeneratedTokens()
	startIdx := 0
	for ; startIdx < len(txOuts); startIdx++ {
		txOut := txOuts[startIdx]
		privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
		if err != nil {
			return nil, err
		}
		if privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre ||
			privacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
			continue
		}

		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			// todo: error? consider the case that there is no AutTokens.
			// the error is assuming that this function is called with pre-condition that there must be AutTokens.
			// i.e. numCTAUTTokens > 0, this should be claimed explicitly.
			return nil, fmt.Errorf("expect privacy level %d but got %d",
				abecryptoxkey.PrivacyLevelPSEUDONYMCT, privacyLevel)
		}
		// todo: give the comments
		// The AutHostTxos are at the start positions of Pseudonym-privacy Txos.
		break
	}

	if startIdx+numCTAUTTokens > len(txOuts) {
		return nil, fmt.Errorf("claim %d outputs for CTAUT but only remain %d outputs in host transaction",
			numCTAUTTokens, len(txOuts)-startIdx)
	}

	// todo(ctaut): seems not correct. it is possible startIdx is not hosting ctaut. need define the rules
	generatedTokens := make([]*AutToken, numCTAUTTokens)
	for i := 0; i < numCTAUTTokens; i++ {
		index := uint8(startIdx + i)
		txOut := txOuts[index]

		coinAddress, err := CheckHostTxoParasiticity(txHash, index, txOut)
		if err != nil {
			return nil, err
		}

		generatedTokens[i] = &AutToken{
			Version: script.Version(),
			HostOutPoint: HostOutPoint{
				TxHash: txHash,
				Index:  index,
			},
			ValueScript: nil, // nil for root coin, fill out for coin later
			CoinAddress: coinAddress,
		}
	}

	switch ctAUTScript := script.(type) {
	case *RegistrationScript:
		// no value script need to assign
	case *ReRegistrationScript:
		// no value script need to assign
	case *MintScript: // todo: add TransferScript, BurnScript here?
		for i := 0; i < numCTAUTTokens; i++ {
			err := RuleCheckOnTxoVersionType(generatedTokens[i].Version, ctAUTScript.serializedAutTxos[i])
			if err != nil {
				return nil, err
			}

			generatedTokens[i].ValueScript = ctAUTScript.serializedAutTxos[i]
		}
	case *TransferScript:
		for i := 0; i < numCTAUTTokens; i++ {
			err := RuleCheckOnTxoVersionType(generatedTokens[i].Version, ctAUTScript.serializedAutTxos[i])
			if err != nil {
				return nil, err
			}

			generatedTokens[i].ValueScript = ctAUTScript.serializedAutTxos[i]
		}
	case *BurnScript:
		for i := 0; i < numCTAUTTokens; i++ {
			err := RuleCheckOnTxoVersionType(generatedTokens[i].Version, ctAUTScript.serializedAutTxos[i])
			if err != nil {
				return nil, err
			}

			generatedTokens[i].ValueScript = ctAUTScript.serializedAutTxos[i]
		}
	default:
		return nil, fmt.Errorf("unexpected aut transaction type %d", script.Type())
	}

	return generatedTokens, nil
}

// todo(ctaut): define the rules on the mint/update threshold.
// todo: confirm, this is only a minimum check, say,
// each claimed issuer has at least one corresponding AutToken,
// and each CTAUToken has has corresponding issuer.
func matchIssuers(issuers []*AutIssuer, outputs []*AutToken) error {
	claimedIssuersByCoinAddress := map[string]struct{}{}
	for i := 0; i < len(issuers); i++ {
		coinAddressStr := hex.EncodeToString(issuers[i].CoinAddress())
		// ensure no duplicates one
		if _, ok := claimedIssuersByCoinAddress[coinAddressStr]; ok {
			return fmt.Errorf("claimed repeated issuers")
		}
		claimedIssuersByCoinAddress[coinAddressStr] = struct{}{}
	}
	if len(claimedIssuersByCoinAddress) != len(issuers) {
		return fmt.Errorf("claimed repeated issue token")
	}

	//	todo(ctaut): should not have coinAddress at this layer, how to match the token and actual coin address
	tokenCoinAddresses := map[string]struct{}{}
	for i := 0; i < len(outputs); i++ {
		coinAddressStr := hex.EncodeToString(outputs[i].CoinAddress)
		if _, ok := tokenCoinAddresses[coinAddressStr]; !ok {
			tokenCoinAddresses[coinAddressStr] = struct{}{}
		} else {
			// do nothing
			// allow repeated, does not matter
		}
	}
	// compare with claimed issueTokens
	if len(tokenCoinAddresses) != len(claimedIssuersByCoinAddress) {
		return fmt.Errorf("claimed mismatched issue token")
	}
	for coinAddress := range tokenCoinAddresses {
		if _, ok := claimedIssuersByCoinAddress[coinAddress]; !ok {
			return fmt.Errorf("use unclaimed issuer token")
		}
		delete(claimedIssuersByCoinAddress, coinAddress)
	}
	if len(claimedIssuersByCoinAddress) != 0 {
		return fmt.Errorf("claim unused issuer token")
	}
	return nil
}

func RuleCheckOnTxoVersionType(autScriptVersion uint32, valueScript []byte) error {
	autTxo := &ctautwire.AutTxo{}
	err := autTxo.Deserialize(valueScript)
	if err != nil {
		return err
	}
	autTxoType, err := abecryptox.GetAutTxoType(autTxo)
	if err != nil {
		return fmt.Errorf("fail to get last aut txo type from burn script: %v", err)
	}

	err = abecryptox.AutRuleCheckOnTxoVersionType(autScriptVersion, autTxoType)
	if err != nil {
		return fmt.Errorf("fail to pass the AutRuleCheckOnTxoVersionType: %v", err)
	}
	return nil
}
