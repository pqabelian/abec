package ctaut

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

func writePrefix(b bytes.Buffer, ctautTxType TransactionType, identifier []byte) error {
	_, err := b.WriteString(CommonPrefix)
	if err != nil {
		return err
	}

	err = b.WriteByte(ctautTxType)
	if err != nil {
		return err
	}
	return WriteVarBytes(&b, identifier)
}

func readPrefix(r io.Reader, expectedCtAutTxType TransactionType) ([]byte, error) {
	commprefix := make([]byte, len(CommonPrefix))
	_, err := io.ReadFull(r, commprefix)
	if err != nil {
		return nil, ErrNonAutTx
	}
	if !bytes.Equal(commprefix, []byte(CommonPrefix)) {
		return nil, ErrNonAutTx
	}

	typeByte := make([]byte, 1)
	_, err = io.ReadFull(r, typeByte)
	if err != nil {
		return nil, err
	}
	if typeByte[0] != expectedCtAutTxType {
		return nil, ErrInValidAUTTx
	}

	identifier, err := ReadVarBytes(r, IdentifierLength, "identifier")
	if err != nil {
		return nil, err
	}
	if len(identifier) != IdentifierLength {
		return nil, ErrInValidAUTTx
	}
	return identifier, nil
}

func writeIssuerTokens(b bytes.Buffer, issuerTokens [][]byte) error {
	err := WriteVarInt(&b, uint64(len(issuerTokens)))
	if err != nil {
		return err
	}
	for _, issuer := range issuerTokens {
		err = WriteVarBytes(&b, issuer[:])
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
	if numIssuer == 0 || numIssuer > MaxIssuerNum {
		return nil, ErrInValidAUTTx
	}

	claimedCoinAddresses := map[string]struct{}{}
	issuerTokens := make([][]byte, numIssuer)
	for i := 0; i < len(issuerTokens); i++ {
		issuerTokens[i], err = ReadVarBytes(r, IssuerTokenLength, "issuerToken")
		if err != nil {
			return nil, err
		}
		if len(issuerTokens[i]) != IssuerTokenLength { // todo(ctaut): need to discuss and confirm
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

func writeWitnessHash(b bytes.Buffer, witnessHash chainhash.Hash) error {
	return WriteVarBytes(&b, witnessHash[:])
}
func readWitnessHash(r io.Reader) (chainhash.Hash, error) {
	// todo(ctaut): why use var bytes? it increases the NewHash() part.
	// todo(ctaut): "memo" is not correct.
	witnessHashBytes, err := ReadVarBytes(r, chainhash.HashSize, "memo")
	if err != nil {
		return chainhash.InvalidHash, err
	}
	witnessHash, err := chainhash.NewHash(witnessHashBytes)
	if err != nil {
		return chainhash.InvalidHash, err
	}
	return *witnessHash, nil
}

// todo(ctaut): why define this function?
func writeAutMemo(b bytes.Buffer, autMemo []byte) error {
	return WriteVarBytes(&b, autMemo)
}

// todo(ctaut): the length check does not make sense, since it is checked in ReadVarBytes.
func readAutMemo(r io.Reader) ([]byte, error) {
	autMemo, err := ReadVarBytes(r, MaxAUTMemoLength, "autmemo")
	if err != nil {
		return nil, err
	}
	if len(autMemo) > MaxAUTMemoLength {
		return nil, ErrInValidAUTTx
	}
	return autMemo, nil
}

// todo(ctaut): why define this function?
func writeMemo(b bytes.Buffer, memo []byte) error {
	return WriteVarBytes(&b, memo)
}

// todo(ctaut): the length check does not make sense, since it is checked in ReadVarBytes.
func readMemo(r io.Reader) ([]byte, error) {
	memo, err := ReadVarBytes(r, MaxAUTTxMemoLength, "memo")
	if err != nil {
		return nil, err
	}
	if len(memo) > MaxAUTTxMemoLength {
		return nil, ErrInValidAUTTx
	}
	return memo, nil
}

// todo(ctaut): add 's' to the name?
func writeCTAUTTxoScript(b bytes.Buffer, scripts [][]byte) error {
	err := WriteVarInt(&b, uint64(len(scripts)))
	if err != nil {
		return err
	}
	for _, txoScript := range scripts {
		err = WriteVarBytes(&b, txoScript)
		if err != nil {
			return err
		}
	}
	return nil
}
func readCTAUTTxoScript(r io.Reader, expectedLength int) ([][]byte, error) {
	var numOutAutCoins uint64
	var err error
	if numOutAutCoins, err = ReadVarInt(r); err != nil {
		return nil, err
	}
	if uint64(expectedLength) != numOutAutCoins {
		return nil, errors.New("mis-match output coin")
	}

	ctAUTTxoScripts := make([][]byte, numOutAutCoins)
	for i := 0; i < len(ctAUTTxoScripts); i++ {
		ctAUTTxoScripts[i], err = ReadVarBytes(r, MaxAUTTxoScriptLength, "an AUT with invalid txo script")
		if err != nil {
			return nil, err
		}
		if len(ctAUTTxoScripts[i]) > MaxAUTTxoScriptLength {
			// todo(ctaut): the check does not make sense
			// todo(ctaut): the length is not correct.
			return nil, ErrInValidAUTTx
		}
	}
	return ctAUTTxoScripts, nil
}

// todo(ctaut): add comment to define the rules
// todo(ctaut): HostTxoSanityCheck
func CheckTxoSanity(txHash chainhash.Hash, outputIndex int, txOut *wire.TxOutAbe) ([]byte, error) {
	privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
	if err != nil {
		return nil, fmt.Errorf("fail to extract the privacy level from transaction %s:%s", txHash, err.Error())
	}
	if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
		return nil, fmt.Errorf("invalid privacy level to %d-th output from transaction %s", outputIndex, txHash)
	}

	coinAddress, coinValue, err := abecryptox.PseudonymTxoCoinParse(txOut)
	if err != nil {
		return nil, fmt.Errorf("fail to parse %d-th output as an pseudonym txo from transaction %s", outputIndex, txHash)
	}
	if coinValue != 1 {
		return nil, fmt.Errorf("invalid value from %d-th output from transaction %s as AUT coin", outputIndex, txHash)
	}
	return coinAddress, nil
}

// todo(ctaut): add comments to define the rules
func populateCTAUTOutputs(autTransaction Transaction, msgTx *wire.MsgTxAbe) error {
	startIdx := 0
	for ; startIdx < len(msgTx.TxOuts); startIdx++ {
		txOut := msgTx.TxOuts[startIdx]
		privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
		if err != nil {
			return err
		}
		if privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre ||
			privacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
			continue
		}

		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			return fmt.Errorf("expect privacy level %d but got %d",
				abecryptoxkey.PrivacyLevelPSEUDONYMCT, privacyLevel)
		}
		break
	}

	// todo(ctaut): NumTxOutputs() here is a typically inappropriate use.
	if startIdx+autTransaction.NumTxOutputs() > len(msgTx.TxOuts) {
		return fmt.Errorf("claim %d outputs for CTAUT but only remain %d outputs in host transaction",
			autTransaction.NumTxOutputs(), len(msgTx.TxOuts)-startIdx)
	}

	// todo(ctaut): seems not correct. it is possible startIdx is not hosting ctaut. need define the rules
	txHash := msgTx.TxHash()
	autTxOuts := make([]*CTAUTToken, autTransaction.NumTxOutputs())
	for i := 0; i < autTransaction.NumTxOutputs(); i++ {
		index := startIdx + i
		txOut := msgTx.TxOuts[index]

		coinAddress, err := CheckTxoSanity(txHash, index, txOut)
		if err != nil {
			return err
		}

		autTxOuts[i] = &CTAUTToken{
			Version: txOut.Version,
			OutPoint: OutPoint{
				TxHash: txHash,
				Index:  uint8(index),
			},
			ValueScript: nil, // nil for root coin, fill out for coin later
			CoinAddress: coinAddress,
		}
	}

	return autTransaction.setTxOutputs(autTxOuts)
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
