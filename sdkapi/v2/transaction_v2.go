package v2

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/wire"
)

var TxVersionV2 = wire.TxVersion_Height_MLPAUT_300000

func CreateTransferTxByRootSeedV2(serializedTransferTxRequestDesc []byte, rootSeeds []*CryptoRootSeed) (serializedTxFull []byte, txId *TxId, err error) {
	txRequestDesc, err := deserializeTransferTxRequestDesc(serializedTransferTxRequestDesc)
	if err != nil {
		return nil, nil, err
	}

	// abeTxInputDescs []*AbeTxInputDesc
	//	sanity checks
	inputNum := len(txRequestDesc.TxRequestInputDescs)
	abeTxInputDescs := make([]*abecryptox.AbeTxInputDescByRootSeeds, inputNum)
	for i := 0; i < inputNum; i++ {
		txRequestInputDesc := txRequestDesc.TxRequestInputDescs[i]
		rootSeed := rootSeeds[i]
		ok, value, err := abecryptox.TxoCoinReceiveByRootSeeds(txRequestInputDesc.txoRing.TxOuts[txRequestInputDesc.sidx], rootSeed.coinValueKeyRootSeed, rootSeed.coinDetectorRootKey)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			errStr := fmt.Sprintf("the %d-th cryptoKey cannot extract coin-value from the corresponding TxRequestInputDesc", i)
			return nil, nil, errors.New(errStr)
		}

		abeTxInputDescs[i] = abecryptox.NewAbeTxInputDescByRootSeeds(
			txRequestInputDesc.txoRing,
			txRequestInputDesc.sidx,
			rootSeed.cryptoScheme,
			rootSeed.privacyLevel,
			rootSeed.coinSpendKeyRootSeed,
			rootSeed.coinSerialNumberKeyRootSeed,
			rootSeed.coinValueKeyRootSeed,
			rootSeed.coinDetectorRootKey,
			value, // amount in txo as input
		)
	}

	//	abeTxOutputDescs []*AbeTxOutputDesc
	outputNum := len(txRequestDesc.TxRequestOutputDescs)
	abeTxOutputDescs := make([]*abecryptox.AbeTxOutputDesc, outputNum)
	for i := 0; i < outputNum; i++ {
		txRequestOutputDesc := txRequestDesc.TxRequestOutputDescs[i]
		abeTxOutputDescs[i] = abecryptox.NewAbeTxOutDesc(txRequestOutputDesc.cryptoAddress, txRequestOutputDesc.value)
	}

	// adjust the order of output descs
	// adjust the order of output descs
	sort.SliceStable(abeTxOutputDescs, func(i, j int) bool {
		outputIAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(abeTxOutputDescs[i].CryptoAddress())
		outputJAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(abeTxOutputDescs[j].CryptoAddress())
		if outputIAddressPrivacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM && outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			return true
		}
		return false
	})

	transferTxMsgTemplate, err := abecryptox.CreateTransferTxMsgTemplateByRootSeeds(TxVersionV2, abeTxInputDescs, abeTxOutputDescs, txRequestDesc.TxFee, txRequestDesc.TxMemo)
	if err != nil {
		return nil, nil, err
	}

	transferTxMsg, err := abecryptox.TransferTxGenByRootSeeds(abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)
	if err != nil {
		return nil, nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, transferTxMsg.SerializeSizeFull()))
	err = transferTxMsg.SerializeFull(buf)
	if err != nil {
		return nil, nil, err
	}

	trTxId := TxId(transferTxMsg.TxId())

	return buf.Bytes(), &trTxId, nil
}

//	todo(MLP): todo
//
// CreateTransferTxByCryptoKeys would use the result called by BuildTransferTxRequestDescFromBlocks or BuildTransferTxRequestDescFromTxoRings as the unsigned transaction
// and the cryptoKeys should be matched in order for the input in unsigned transaction
func CreateTransferTxByCryptoKeysV2(serializedTransferTxRequestDesc []byte, cryptoKeys []*CryptoKey) (serializedTxFull []byte, txId *TxId, err error) {
	txRequestDesc, err := deserializeTransferTxRequestDesc(serializedTransferTxRequestDesc)
	if err != nil {
		return nil, nil, err
	}

	// abeTxInputDescs []*AbeTxInputDesc
	//	sanity checks
	inputNum := len(txRequestDesc.TxRequestInputDescs)
	if inputNum != len(cryptoKeys) {
		return nil, nil, fmt.Errorf("CreateTransferTxByCryptoKeys: the number of input keys does not match the number of TransferTxRequestDesc's inputs")
	}

	abeTxInputDescs := make([]*abecryptox.AbeTxInputDescByKeys, inputNum)
	for i := 0; i < inputNum; i++ {
		txRequestInputDesc := txRequestDesc.TxRequestInputDescs[i]
		cryptoKey := cryptoKeys[i]

		if valid, err := abecryptoxkey.CryptoAddressKeysVerify(cryptoKey.cryptoAddress, cryptoKey.cryptoSpsk, cryptoKey.cryptoSnsk, cryptoKey.cryptoVsk, cryptoKey.cryptoDetectorKey); !valid {
			return nil, nil, fmt.Errorf("GenerateTransferTx: %s", err)
		}

		var copyedVskBytes []byte
		if len(cryptoKey.cryptoVsk) != 0 {
			copyedVskBytes = make([]byte, len(cryptoKey.cryptoVsk))
			copy(copyedVskBytes, cryptoKey.cryptoVsk)
		}

		ok, value, err := abecryptox.TxoCoinReceiveByKeys(txRequestInputDesc.txoRing.TxOuts[txRequestInputDesc.sidx], cryptoKey.cryptoAddress, copyedVskBytes)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			errStr := fmt.Sprintf("the %d-th cryptoKey cannot extract coin-value from the corresponding TxRequestInputDesc", i)
			return nil, nil, errors.New(errStr)
		}

		abeTxInputDescs[i] = abecryptox.NewAbeTxInputDescByKeys(
			txRequestInputDesc.txoRing,
			txRequestInputDesc.sidx,
			cryptoKey.cryptoAddress,
			cryptoKey.cryptoSpsk,
			cryptoKey.cryptoSnsk,
			cryptoKey.cryptoVsk,
			cryptoKey.cryptoDetectorKey,
			value, // amount in txo as input
		)
	}

	//	abeTxOutputDescs []*AbeTxOutputDesc
	outputNum := len(txRequestDesc.TxRequestOutputDescs)
	abeTxOutputDescs := make([]*abecryptox.AbeTxOutputDesc, outputNum)
	for i := 0; i < outputNum; i++ {
		txRequestOutputDesc := txRequestDesc.TxRequestOutputDescs[i]
		abeTxOutputDescs[i] = abecryptox.NewAbeTxOutDesc(txRequestOutputDesc.cryptoAddress, txRequestOutputDesc.value)
	}

	// adjust the order of output descs
	sort.SliceStable(abeTxOutputDescs, func(i, j int) bool {
		outputIAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(abeTxOutputDescs[i].CryptoAddress())
		outputJAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(abeTxOutputDescs[j].CryptoAddress())
		if outputIAddressPrivacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM && outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			return true
		}
		return false
	})

	transferTxMsgTemplate, err := abecryptox.CreateTransferTxMsgTemplateByKeys(TxVersionV2, abeTxInputDescs, abeTxOutputDescs, txRequestDesc.TxFee, txRequestDesc.TxMemo)
	if err != nil {
		return nil, nil, err
	}

	transferTxMsg, err := abecryptox.TransferTxGenByKeys(abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)
	if err != nil {
		return nil, nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, transferTxMsg.SerializeSizeFull()))
	err = transferTxMsg.SerializeFull(buf)
	if err != nil {
		return nil, nil, err
	}

	trTxId := TxId(transferTxMsg.TxId())

	return buf.Bytes(), &trTxId, nil
}
