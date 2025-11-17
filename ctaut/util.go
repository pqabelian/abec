package ctaut

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math"

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

func writePrefix(b *bytes.Buffer, scriptVersion uint32, autScriptType AutScriptType, autIdentifier [AutIdentifierLength]byte) error {
	err := WriteFixedBytes(b, []byte(commonPrefix))
	if err != nil {
		return err
	}

	err = WriteVarInt(b, uint64(scriptVersion))
	if err != nil {
		return err
	}

	err = WriteByte(b, autScriptType)
	if err != nil {
		return err
	}

	return WriteFixedBytes(b, autIdentifier[:])
}

// todo: discuss: shall remove expectedCtAutTxType? leave the check to the caller
func readPrefix(r io.Reader, expectedAutScriptType AutScriptType) (uint32, [AutIdentifierLength]byte, AutScriptType, error) {
	var res [AutIdentifierLength]byte

	commprefix, err := ReadFixedBytes(r, len(commonPrefix))
	if err != nil {
		return 0, res, 0, ErrNonAutTx
	}
	if !bytes.Equal(commprefix, []byte(commonPrefix)) {
		return 0, res, 0, ErrNonAutTx
	}

	scriptVersion, err := ReadVarInt(r)
	if err != nil {
		return 0, res, 0, err
	}
	if scriptVersion > math.MaxUint32 {
		return 0, res, 0, ErrInValidAUTTx
	}

	autScriptType, err := ReadByte(r)
	if err != nil {
		return 0, res, 0, err
	}
	if autScriptType != expectedAutScriptType {
		return 0, res, 0, ErrInValidAUTTx
	}

	identifier, err := ReadFixedBytes(r, AutIdentifierLength)
	if err != nil {
		return 0, res, 0, err
	}
	copy(res[:], identifier)

	return uint32(scriptVersion), res, autScriptType, nil
}

func writeIssuerTokens(b *bytes.Buffer, issuerTokens [][]byte) error {
	err := WriteVarInt(b, uint64(len(issuerTokens)))
	if err != nil {
		return err
	}
	for _, issuer := range issuerTokens {
		err = WriteVarBytes(b, issuer[:])
		if err != nil {
			return err
		}
	}
	return nil
}

// todo(ctaut): numIssuer == 0 should be checked here?
func readIssuerTokens(r io.Reader) ([][]byte, error) {
	var numIssuer uint64
	var err error
	if numIssuer, err = ReadVarInt(r); err != nil {
		return nil, err
	}

	claimedCoinAddresses := map[string]struct{}{}
	issuerTokens := make([][]byte, numIssuer)
	for i := 0; i < len(issuerTokens); i++ {
		issuerTokens[i], err = ReadVarBytes(r, issuerTokenLength, "issuerToken")
		if err != nil {
			return nil, err
		}
		if len(issuerTokens[i]) != issuerTokenLength { // todo(ctaut): need to discuss and confirm
			return nil, ErrInValidAUTTx
		}

		key := hex.EncodeToString(issuerTokens[i])
		if _, ok := claimedCoinAddresses[key]; ok { // todo(ctaut): cannot repeat? consistent with the design?
			return nil, ErrInValidAUTTx
		}
		claimedCoinAddresses[key] = struct{}{}
	}
	if len(claimedCoinAddresses) != int(numIssuer) {
		return nil, ErrInValidAUTTx
	}

	return issuerTokens, nil
}

// todo: discuss to make a simple and symmetric; seems to package the read and write too much, so that the logic is a little strange.
// todo: e.g., the serialize and deserialize Hash does not need package.
func writeWitnessHash(b *bytes.Buffer, witnessHash chainhash.Hash) error {
	//return WriteVarBytes(b, witnessHash[:])
	_, err := b.Write(witnessHash[:])
	return err
}

func readWitnessHash(r io.Reader) (chainhash.Hash, error) {
	// todo(ctaut): why use var bytes? it increases the NewHash() part.
	// todo(ctaut): "memo" is not correct.
	//witnessHashBytes, err := ReadVarBytes(r, chainhash.HashSize, "memo")
	//if err != nil {
	//	return chainhash.InvalidHash, err
	//}
	//witnessHash, err := chainhash.NewHash(witnessHashBytes)
	//if err != nil {
	//	return chainhash.InvalidHash, err
	//}
	//return *witnessHash, nil

	rstHash := chainhash.Hash{}
	// todo: why ReadFull is not symmetric with b.Write
	_, err := io.ReadFull(r, rstHash[:])
	return rstHash, err

}

// todo(ctaut): why define this function?
// todo: only one caller
func writeAutMemo(b *bytes.Buffer, autMemo []byte) error {
	return WriteVarBytes(b, autMemo)
}

// todo(ctaut): the length check does not make sense, since it is checked in ReadVarBytes.
func readAutMemo(r io.Reader) ([]byte, error) {
	autMemo, err := ReadVarBytes(r, MaxAutMemoLength, "autmemo")
	if err != nil {
		return nil, err
	}
	if len(autMemo) > MaxAutMemoLength {
		return nil, ErrInValidAUTTx
	}
	return autMemo, nil
}

// todo(ctaut): why define this function?
// the name is not clear. directly call in the serialize/deserialize
func writeMemo(b *bytes.Buffer, memo []byte) error {
	return WriteVarBytes(b, memo)
}

// todo(ctaut): the length check does not make sense, since it is checked in ReadVarBytes.
func readMemo(r io.Reader) ([]byte, error) {
	memo, err := ReadVarBytes(r, MaxMemoLength, "memo")
	if err != nil {
		return nil, err
	}
	if len(memo) > MaxMemoLength {
		return nil, ErrInValidAUTTx
	}
	return memo, nil
}

// todo(ctaut): add 's' to the name?
func writeCTAUTTxoScripts(b *bytes.Buffer, scripts [][]byte) error {
	err := WriteVarInt(b, uint64(len(scripts)))
	if err != nil {
		return err
	}
	for _, txoScript := range scripts {
		err = WriteVarBytes(b, txoScript)
		if err != nil {
			return err
		}
	}
	return nil
}
func readCTAUTTxoScript(r io.Reader, expectedCTTokenLength int, expectedPlainTokenLength int) ([][]byte, error) {
	var err error

	var numAutCoins uint64
	if numAutCoins, err = ReadVarInt(r); err != nil {
		return nil, err
	}
	if int(numAutCoins) != expectedCTTokenLength+expectedPlainTokenLength {
		return nil, ErrInValidAUTTx
	}

	valueScripts := make([][]byte, numAutCoins)
	for i := uint64(0); i < numAutCoins; i++ {
		valueScripts[i], err = ReadVarBytes(r, MaxAutValueScriptLength, "valueScript")
		if err != nil {
			return nil, err
		}
	}

	for i := 0; i < expectedCTTokenLength; i++ {
		autTxo := &ctautwire.AutTxo{}
		err = autTxo.Deserialize(valueScripts[i])
		if err != nil {
			return nil, err
		}
		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return nil, err
		}
		if autTxoType != abecryptox.AutTxoTypeHidden {
			return nil, ErrInValidAUTTx
		}
	}
	for i := expectedCTTokenLength; i < expectedCTTokenLength+expectedPlainTokenLength; i++ {
		autTxo := &ctautwire.AutTxo{}
		err = autTxo.Deserialize(valueScripts[i])
		if err != nil {
			return nil, err
		}
		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return nil, err
		}
		if autTxoType != abecryptox.AutTxoTypePublic {
			return nil, ErrInValidAUTTx
		}
	}

	return valueScripts, nil
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
func GetGeneratedAutTokens(script AutScript, txHash chainhash.Hash, txOuts []*wire.TxOutAbe) ([]*CTAUTToken, error) {
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
	generatedTokens := make([]*CTAUTToken, numCTAUTTokens)
	for i := 0; i < numCTAUTTokens; i++ {
		index := uint8(startIdx + i)
		txOut := txOuts[index]

		coinAddress, err := CheckHostTxoParasiticity(txHash, index, txOut)
		if err != nil {
			return nil, err
		}

		generatedTokens[i] = &CTAUTToken{
			Version: txOut.Version,
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
			err := RuleCheckOnTxoVersionType(generatedTokens[i].Version, ctAUTScript.valueScripts[i])
			if err != nil {
				return nil, err
			}

			generatedTokens[i].ValueScript = ctAUTScript.valueScripts[i]
		}
	case *TransferScript:
		for i := 0; i < numCTAUTTokens; i++ {
			err := RuleCheckOnTxoVersionType(generatedTokens[i].Version, ctAUTScript.valueScripts[i])
			if err != nil {
				return nil, err
			}

			generatedTokens[i].ValueScript = ctAUTScript.valueScripts[i]
		}
	case *BurnScript:
		for i := 0; i < numCTAUTTokens; i++ {
			err := RuleCheckOnTxoVersionType(generatedTokens[i].Version, ctAUTScript.valueScripts[i])
			if err != nil {
				return nil, err
			}

			generatedTokens[i].ValueScript = ctAUTScript.valueScripts[i]
		}
	default:
		return nil, fmt.Errorf("unexpected aut transaction type %d", script.Type())
	}

	return generatedTokens, nil
}

// todo(ctaut): define the rules on the mint/update threshold.
func matchIssuerTokens(issuerTokens [][]byte, outputs []*CTAUTToken) error {
	claimedIssuerTokens := map[string]struct{}{}
	for i := 0; i < len(issuerTokens); i++ {
		coinAddress := issuerTokens[i]
		key := hex.EncodeToString(coinAddress)
		// ensure no duplicates one
		if _, ok := claimedIssuerTokens[key]; ok {
			return fmt.Errorf("claimed repeated issue token")
		}
		claimedIssuerTokens[key] = struct{}{}
	}
	if len(claimedIssuerTokens) != len(issuerTokens) {
		return fmt.Errorf("claimed repeated issue token")
	}

	//	todo(ctaut): should not have coinAddress at this layer, how to match the token and actual coin address
	tokenCoinAddresses := map[string]struct{}{}
	for i := 0; i < len(outputs); i++ {
		key := hex.EncodeToString(outputs[i].CoinAddress)
		if _, ok := tokenCoinAddresses[key]; !ok {
			tokenCoinAddresses[key] = struct{}{}
		}
	}
	// compare with claimed issueTokens
	if len(tokenCoinAddresses) != len(claimedIssuerTokens) {
		return fmt.Errorf("claimed mismatched issue token")
	}
	for coinAddress := range tokenCoinAddresses {
		if _, ok := claimedIssuerTokens[coinAddress]; !ok {
			return fmt.Errorf("use unclaimed issuer token")
		}
		delete(claimedIssuerTokens, coinAddress)
	}
	if len(claimedIssuerTokens) != 0 {
		return fmt.Errorf("claim unused issuer token")
	}
	return nil
}

func RuleCheckOnTxoVersionType(hostTxoVersion uint32, valueScript []byte) error {
	autTxo := &ctautwire.AutTxo{}
	err := autTxo.Deserialize(valueScript)
	if err != nil {
		return err
	}
	autTxoType, err := abecryptox.GetAutTxoType(autTxo)
	if err != nil {
		return fmt.Errorf("fail to get last aut txo type from burn script: %v")
	}

	err = abecryptox.AutRuleCheckOnTxoVersionType(hostTxoVersion, autTxoType)
	if err != nil {
		return fmt.Errorf("fail to pass the AutRuleCheckOnTxoVersionType: %v", err)
	}
	return nil
}
