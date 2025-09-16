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
		if len(issuerTokens[i]) != IssuerTokenLength {
			return nil, ErrInValidAUTTx
		}

		key := hex.EncodeToString(issuerTokens[i])
		if _, ok := claimedCoinAddresses[key]; ok {
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

func writeAutMemo(b bytes.Buffer, autMemo []byte) error {
	return WriteVarBytes(&b, autMemo)
}
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

func writeMemo(b bytes.Buffer, memo []byte) error {
	return WriteVarBytes(&b, memo)
}
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
			return nil, ErrInValidAUTTx
		}
	}
	return ctAUTTxoScripts, nil
}

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

	if startIdx+autTransaction.NumTxOutputs() > len(msgTx.TxOuts) {
		return fmt.Errorf("claim %d outputs for CTAUT but only remain %d outputs in host transaction",
			autTransaction.NumTxOutputs(), len(msgTx.TxOuts)-startIdx)
	}

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
			OutPoint: OutPoint{
				TxHash: txHash,
				Index:  uint8(index),
			},
			Version:     txOut.Version,
			ValueScript: nil, // nil for root coin, fill out for coin later
			CoinAddress: coinAddress,
		}
	}

	return autTransaction.setTxOutputs(autTxOuts)
}
