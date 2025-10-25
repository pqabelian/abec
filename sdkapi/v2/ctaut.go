package v2

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/ctaut"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
)

const TxVersionCTAUT = wire.TxVersion_Height_450000_Aconcagua
const CTAUTIdentifierLength = ctaut.CTAUTIdentifierLength

type CTAUTScriptType = ctaut.CTAUTScriptType

const (
	CTAUTTypeRegistration   CTAUTScriptType = ctaut.Registration
	CTAUTTypeReRegistration CTAUTScriptType = ctaut.ReRegistration
	CTAUTTypeMint           CTAUTScriptType = ctaut.Mint
	CTAUTTypeTransfer       CTAUTScriptType = ctaut.Transfer
	CTAUTTypeBurn           CTAUTScriptType = ctaut.Burn
)

type CTAUTScript = ctaut.CTAUTScript

type CTAUTRegisterScript ctaut.RegistrationScript

func NewRegistrationScript(
	version uint32,
	ctAutName []byte,
	ctAutSymbol []byte,
	baseUnitName []byte,
	subUnitName []byte,
	unitScale uint64,
	ctAutMemo []byte,
	plannedTotalAmount uint64,
	issuerTokens [][]byte,
	mintThreshold uint8,
	reregisterThreshold uint8,
	expireHeight int32,
	outAutRootTokenNum uint8,
	memo []byte,
) ([]byte, []byte, error) {
	script := ctaut.NewRegistrationScript(
		version,
		ctAutName,
		ctAutSymbol,
		baseUnitName,
		subUnitName,
		unitScale,
		ctAutMemo,
		plannedTotalAmount,
		issuerTokens,
		mintThreshold,
		reregisterThreshold,
		expireHeight,
		outAutRootTokenNum,
		memo)
	registerScript, err := script.Serialize()
	if err != nil {
		return nil, nil, err
	}

	return registerScript, nil, nil
}

type CTAUTReRegisterScript = ctaut.ReRegistrationScript

func NewReRegistrationScript(
	version uint32,
	ctAutIdentifier [CTAUTIdentifierLength]byte,
	ctAutMemo []byte,
	plannedTotalAmount uint64,
	issuerTokens [][]byte,
	mintThreshold uint8,
	reregisterThreshold uint8,
	expireHeight int32,
	inAutRootTokenNum uint8,
	outAutRootTokenNum uint8,
	memo []byte,
) ([]byte, []byte, error) {
	script := ctaut.NewReRegistrationScript(
		version,
		ctAutIdentifier,
		ctAutMemo,
		plannedTotalAmount,
		issuerTokens,
		mintThreshold,
		reregisterThreshold,
		expireHeight,
		inAutRootTokenNum,
		outAutRootTokenNum,
		memo,
	)
	reRegisterScript, err := script.Serialize()
	if err != nil {
		return nil, nil, err
	}

	return reRegisterScript, nil, nil
}

type CTAUTMintScript = ctaut.MintScript

func NewMintScript(
	version uint32,
	ctAutIdentifier [CTAUTIdentifierLength]byte,
	vin uint64,
	inAutRootTokenNum uint8,
	autTxOutputDescs []*AutTxOutputDesc,
	memo []byte,
) ([]byte, []byte, error) {
	var outCTAutTokenNum uint8
	var outPlainAutTokenNum uint8

	outputDescs := make([]*abecryptox.AutTxOutputDesc, len(autTxOutputDescs))
	for i := 0; i < len(autTxOutputDescs); i++ {
		var autTxoType abecryptox.AutTxoType
		if len(autTxOutputDescs[i].coinValuePublicKey) == 0 {
			autTxoType = abecryptox.AutTxoTypePublic
			outPlainAutTokenNum++
		} else {
			autTxoType = abecryptox.AutTxoTypeHidden
			outCTAutTokenNum++
		}

		outputDescs[i] = abecryptox.NewAutTxOutDesc(autTxoType, autTxOutputDescs[i].value,
			autTxOutputDescs[i].coinValuePublicKey)

	}

	autCoinbaseTx, err := abecryptox.AutCoinbaseTxGen(TxVersionCTAUT, vin, outputDescs)
	if err != nil {
		return nil, nil, err
	}

	valueScripts := make([][]byte, len(autCoinbaseTx.TxOuts))
	for i, autTxo := range autCoinbaseTx.TxOuts {
		buffer := bytes.NewBuffer(make([]byte, 0, autTxo.SerializeSize()))
		err = autTxo.Serialize(buffer)
		if err != nil {
			return nil, nil, err
		}
		valueScripts[i] = buffer.Bytes()
	}

	witnessHash := chainhash.HashH(autCoinbaseTx.TxWitness)
	script := ctaut.NewMintScript(
		version,
		ctAutIdentifier,
		vin,
		inAutRootTokenNum,
		outCTAutTokenNum,
		outPlainAutTokenNum,
		valueScripts,
		witnessHash,
		memo)
	mintScript, err := script.Serialize()
	if err != nil {
		return nil, nil, err
	}
	return mintScript, autCoinbaseTx.TxWitness, nil
}

type CTAUTTransferScript = ctaut.TransferScript

func NewTransferScript(
	version uint32,
	ctAutIdentifier [CTAUTIdentifierLength]byte,
	autInputDescs []*AutTxInputDesc,
	autOutputDescs []*AutTxOutputDesc,
	memo []byte,
) ([]byte, []byte, error) {

	var inCTAutTokenNum uint8 = 0
	var inPlainAutTokenNum uint8 = 0
	inputDescs := make([]*abecryptox.AutTxInputDesc, len(autInputDescs))
	for i := 0; i < len(autInputDescs); i++ {
		autInputDesc := autInputDescs[i]
		autTxo := &ctautwire.AutTxo{}
		err := autTxo.Deserialize(bytes.NewReader(autInputDesc.ValueScript))
		if err != nil {
			return nil, nil, err
		}

		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return nil, nil, err
		}
		if autTxoType == abecryptox.AutTxoTypeHidden {
			inCTAutTokenNum++
		} else if autTxoType == abecryptox.AutTxoTypePublic {
			inPlainAutTokenNum++
		} else {
			return nil, nil, errors.New("invalid autTxoType")
		}

		inputDescs[i] = abecryptox.NewAutTxInputDesc(
			autTxo,
			autInputDesc.coinValuePublicKey,
			autInputDesc.coinValueSecretKey,
			autInputDesc.value,
		)
	}

	var outCTAutTokenNum uint8
	var outPlainAutTokenNum uint8

	outputDescs := make([]*abecryptox.AutTxOutputDesc, len(autOutputDescs))
	for i := 0; i < len(autOutputDescs); i++ {
		var autTxoType abecryptox.AutTxoType
		if len(autOutputDescs[i].coinValuePublicKey) == 0 {
			autTxoType = abecryptox.AutTxoTypePublic
			outPlainAutTokenNum++
		} else {
			autTxoType = abecryptox.AutTxoTypeHidden
			outCTAutTokenNum++
		}

		outputDescs[i] = abecryptox.NewAutTxOutDesc(autTxoType, autOutputDescs[i].value,
			autOutputDescs[i].coinValuePublicKey)

	}

	autTransferTx, err := abecryptox.AutTransferTxGen(TxVersionCTAUT, inputDescs, outputDescs)
	if err != nil {
		return nil, nil, err
	}

	valueScripts := make([][]byte, len(autTransferTx.TxOuts))
	for i, autTxo := range autTransferTx.TxOuts {
		buffer := bytes.NewBuffer(make([]byte, 0, autTxo.SerializeSize()))
		err = autTxo.Serialize(buffer)
		if err != nil {
			return nil, nil, err
		}
		valueScripts[i] = buffer.Bytes()
	}
	witnessHash := chainhash.HashH(autTransferTx.TxWitness)

	script := ctaut.NewTransferScript(
		version,
		ctAutIdentifier,
		inCTAutTokenNum,
		inPlainAutTokenNum,
		outCTAutTokenNum,
		outPlainAutTokenNum,
		valueScripts,
		witnessHash,
		memo,
	)
	transferScript, err := script.Serialize()
	if err != nil {
		return nil, nil, err
	}
	return transferScript, autTransferTx.TxWitness, nil
}

type CTAUTBurnScript = ctaut.BurnScript

func NewBurnScript(
	version uint32,
	ctAutIdentifier [CTAUTIdentifierLength]byte,
	autInputDescs []*AutTxInputDesc,
	autOutputDescs []*AutTxOutputDesc,
	memo []byte,
) ([]byte, []byte, error) {
	var inCTAutTokenNum uint8 = 0
	var inPlainAutTokenNum uint8 = 0
	inputDescs := make([]*abecryptox.AutTxInputDesc, len(autInputDescs))
	for i := 0; i < len(autInputDescs); i++ {
		autInputDesc := autInputDescs[i]
		autTxo := &ctautwire.AutTxo{}
		err := autTxo.Deserialize(bytes.NewReader(autInputDesc.ValueScript))
		if err != nil {
			return nil, nil, err
		}

		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return nil, nil, err
		}
		if autTxoType == abecryptox.AutTxoTypeHidden {
			inCTAutTokenNum++
		} else if autTxoType == abecryptox.AutTxoTypePublic {
			inPlainAutTokenNum++
		} else {
			return nil, nil, errors.New("invalid autTxoType")
		}

		inputDescs[i] = abecryptox.NewAutTxInputDesc(
			autTxo,
			autInputDesc.coinValuePublicKey,
			autInputDesc.coinValueSecretKey,
			autInputDesc.value,
		)
	}

	var outCTAutTokenNum uint8
	var outPlainAutTokenNum uint8

	outputDescs := make([]*abecryptox.AutTxOutputDesc, len(autOutputDescs))
	for i := 0; i < len(autOutputDescs); i++ {
		var autTxoType abecryptox.AutTxoType
		if len(autOutputDescs[i].coinValuePublicKey) == 0 {
			autTxoType = abecryptox.AutTxoTypePublic
			outPlainAutTokenNum++
		} else {
			autTxoType = abecryptox.AutTxoTypeHidden
			outCTAutTokenNum++
		}

		outputDescs[i] = abecryptox.NewAutTxOutDesc(autTxoType, autOutputDescs[i].value,
			autOutputDescs[i].coinValuePublicKey)

	}

	autTransferTx, err := abecryptox.AutTransferTxGen(TxVersionCTAUT, inputDescs, outputDescs)
	if err != nil {
		return nil, nil, err
	}
	err = abecryptox.AutTransferTxVerify(autTransferTx)
	if err != nil {
		panic(err)
	}

	valueScripts := make([][]byte, len(autTransferTx.TxOuts))
	for i, autTxo := range autTransferTx.TxOuts {
		buffer := bytes.NewBuffer(make([]byte, 0, autTxo.SerializeSize()))
		err = autTxo.Serialize(buffer)
		if err != nil {
			return nil, nil, err
		}
		valueScripts[i] = buffer.Bytes()
	}
	witnessHash := chainhash.HashH(autTransferTx.TxWitness)

	script := ctaut.NewBurnScript(
		version,
		ctAutIdentifier,
		inCTAutTokenNum,
		inPlainAutTokenNum,
		outCTAutTokenNum,
		outPlainAutTokenNum,
		valueScripts,
		witnessHash,
		memo,
	)
	burnScript, err := script.Serialize()
	if err != nil {
		return nil, nil, err
	}
	return burnScript, autTransferTx.TxWitness, nil
}

type AutTxInputDesc struct {
	Version            uint32
	ValueScript        []byte
	coinValuePublicKey []byte
	coinValueSecretKey []byte
	value              uint64
}

func NewAutTxInputDesc(version uint32, valueScript []byte,
	cryptoValuePublicKey []byte, cryptoValueSecretKey []byte, value uint64) (*AutTxInputDesc, error) {
	privacyLevel, coinValuePublicKey, err := abecryptoxkey.CryptoValuePublicKeyParse(cryptoValuePublicKey)
	if err != nil {
		return nil, err
	}
	if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
		return nil, err
	}
	privacyLevel, coinValueSecretKey, err := abecryptoxkey.CryptoValueSecretKeyParse(cryptoValueSecretKey)
	if err != nil {
		return nil, err
	}
	if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
		return nil, err
	}

	return &AutTxInputDesc{
		Version:            version,
		ValueScript:        valueScript,
		coinValuePublicKey: coinValuePublicKey,
		coinValueSecretKey: coinValueSecretKey,
		value:              value,
	}, nil
}

type AutTxOutputDesc struct {
	value              uint64
	coinValuePublicKey []byte // generated by CryptoAddressKeyGen
}

func NewAutTxOutputDesc(value uint64, cryptoAddress []byte, hideValue bool) (*AutTxOutputDesc, error) {
	privacyLevel, _, coinValuePublicKey, err := abecryptoxkey.CryptoAddressParse(cryptoAddress)
	if err != nil {
		return nil, err
	}
	if !hideValue {
		coinValuePublicKey = nil
	}
	if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
		return nil, fmt.Errorf("unexpected privacy level for address")
	}

	return &AutTxOutputDesc{
		value:              value,
		coinValuePublicKey: coinValuePublicKey,
	}, nil
}

type AutTokenType = abecryptox.AutTxoType

const (
	AutTokenTypeHidden = abecryptox.AutTxoTypeHidden
	AutTokenTypePublic = abecryptox.AutTxoTypePublic
)

func ExtractAutTokenValue(version uint32, valueScript []byte, cryptoValuePublicKey []byte, cryptoValueSecretKey []byte) (uint64, AutTokenType, error) {
	autTxo := &ctautwire.AutTxo{}
	err := autTxo.Deserialize(bytes.NewReader(valueScript))
	if err != nil {
		return 0, AutTokenTypeHidden, err
	}

	autTxoType, err := abecryptox.GetAutTxoType(autTxo)
	if err != nil {
		return 0, autTxoType, err
	}
	value, err := abecryptox.ExtractAutTxoValue(autTxo, cryptoValuePublicKey, cryptoValueSecretKey)
	if err != nil {
		return 0, AutTokenTypeHidden, err
	}

	return value, autTxoType, nil
}

func ParseCTAUTScript(txVersion uint32, txID string, memo []byte) (CTAUTScript, error) {
	txHash, err := chainhash.NewHashFromStr(txID)
	if err != nil {
		return nil, err
	}
	return ctaut.ParseCTAUTScript(txVersion, *txHash, memo)
}
func GetGeneratedOutpoints(ctAutScript CTAUTScript, txVersion uint32, txID string, serializedTxOuts [][]byte) (uint32, []*OutPoint, [][]byte, error) {
	if ctAutScript == nil {
		return 0, nil, nil, nil
	}
	abeTxos := make([]*wire.TxOutAbe, len(serializedTxOuts))
	for i := 0; i < len(serializedTxOuts); i++ {
		abeTxo := &wire.TxOutAbe{}
		err := wire.ReadTxOutAbe(bytes.NewReader(serializedTxOuts[i]), 0, txVersion, abeTxo)
		if err != nil {
			return 0, nil, nil, err
		}
		abeTxos[i] = abeTxo
	}
	txHash, err := chainhash.NewHashFromStr(txID)
	if err != nil {
		return 0, nil, nil, err
	}

	generatedTokens, err := ctaut.GetGeneratedCTAUTTokens(ctAutScript, *txHash, abeTxos)
	if err != nil {
		return 0, nil, nil, err
	}

	res := make([]*OutPoint, len(generatedTokens))
	valueScripts := make([][]byte, len(generatedTokens))
	for i := 0; i < len(generatedTokens); i++ {
		token := generatedTokens[i]
		res[i], err = NewOutPointFromTxIdStr(token.HostOutPoint.Hash.String(), uint8(token.HostOutPoint.Index))
		if err != nil {
			return 0, nil, nil, err
		}
		valueScripts[i] = token.ValueScript
	}
	return ctAutScript.Version(), res, valueScripts, nil
}
func GetConsumedOutpoints(serializedTx []byte, rings map[string]*TxoRing) ([]*OutPoint, error) {
	tx, err := abeutil.NewTxAbeFromBytes(serializedTx)
	if err != nil {
		return nil, err
	}
	ctAutScript, err := ctaut.ExtractCTAUTScript(tx.MsgTx())
	if err != nil {
		return nil, err
	}
	if ctAutScript == nil {
		return nil, nil
	}
	err = ctaut.PresetHostOutpointForCTAUT(ctAutScript, tx.MsgTx(), func(ringHash chainhash.Hash) (*wire.TxOutAbe, error) {
		ring := rings[ringHash.String()]
		if ring == nil {
			return nil, fmt.Errorf("no such txo ring found")
		}
		abeTxo := &wire.TxOutAbe{}
		err = wire.ReadTxOutAbe(bytes.NewReader(ring.SerializedTxOuts[0]), 0, ring.Version, abeTxo)
		if err != nil {
			return nil, err
		}
		return abeTxo, nil
	})
	if err != nil {
		return nil, err
	}
	consumedTokens, err := ctAutScript.ConsumedTokens()
	if err != nil {
		return nil, err
	}
	res := make([]*OutPoint, len(consumedTokens))
	for i := 0; i < len(consumedTokens); i++ {
		token := consumedTokens[i]
		res[i], err = NewOutPointFromTxIdStr(token.HostOutPoint.Hash.String(), uint8(token.HostOutPoint.Index))
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}
func CreateTransferTxByRootSeedForCTAUT(serializedTransferTxRequestDesc []byte, autWitness []byte, rootSeeds []*CryptoRootSeed) (serializedTxFull []byte, txId *TxId, err error) {
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
	sort.SliceStable(abeTxOutputDescs, func(i, j int) bool {
		outputIAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(abeTxOutputDescs[i].CryptoAddress())
		outputJAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(abeTxOutputDescs[j].CryptoAddress())

		// Part I  [crypto.PrivacyLevelFullPrivacyPre, crypto.PrivacyLevelFullPrivacyRand]
		// Part II [crypto.PrivacyLevelPseudonym, crypto.PrivacyLevelPseudonymCT]
		if outputIAddressPrivacyLevel < abecryptoxkey.PrivacyLevelPSEUDONYM &&
			outputJAddressPrivacyLevel >= abecryptoxkey.PrivacyLevelPSEUDONYM {
			return true
		}

		// Part I keep the origin order

		// Part II-I [ (crypto.PrivacyLevelPseudonymCT,1) (crypto.PrivacyLevelPseudonymCT,1) ... ]
		if outputIAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT &&
			abeTxOutputDescs[i].Value() == 1 {
			return true
		}
		if outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT &&
			abeTxOutputDescs[j].Value() == 1 {
			return false
		}
		// Part II-II [ (crypto.PrivacyLevelPseudonymCT,*) (crypto.PrivacyLevelPseudonym,*) ]
		if outputIAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT &&
			outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			return true
		}
		if outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT &&
			outputIAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			return false
		}

		return false
	})

	transferTxMsgTemplate, err := abecryptox.CreateTransferTxMsgTemplateByRootSeeds(TxVersionCTAUT, abeTxInputDescs, abeTxOutputDescs, txRequestDesc.TxFee, txRequestDesc.TxMemo)
	if err != nil {
		return nil, nil, err
	}

	transferTxMsg, err := abecryptox.TransferTxGenByRootSeeds(abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)
	if err != nil {
		return nil, nil, err
	}

	// CT-AUT
	transferTxMsg.AutWitness = autWitness

	buf := bytes.NewBuffer(make([]byte, 0, transferTxMsg.SerializeSizeFull()))
	err = transferTxMsg.SerializeFull(buf)
	if err != nil {
		return nil, nil, err
	}

	trTxId := TxId(transferTxMsg.TxId())

	return buf.Bytes(), &trTxId, nil
}
func CreateTransferTxByCryptoKeysForCTAUT(serializedTransferTxRequestDesc []byte, autWitness []byte, cryptoKeys []*CryptoKey) (serializedTxFull []byte, txId *TxId, err error) {
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

		// Part I  [crypto.PrivacyLevelFullPrivacyPre, crypto.PrivacyLevelFullPrivacyRand]
		// Part II [crypto.PrivacyLevelPseudonym, crypto.PrivacyLevelPseudonymCT]
		if outputIAddressPrivacyLevel < abecryptoxkey.PrivacyLevelPSEUDONYM &&
			outputJAddressPrivacyLevel >= abecryptoxkey.PrivacyLevelPSEUDONYM {
			return true
		}

		// Part I keep the origin order

		// Part II-I [ (crypto.PrivacyLevelPseudonymCT,1) (crypto.PrivacyLevelPseudonymCT,1) ... ]
		if outputIAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT &&
			abeTxOutputDescs[i].Value() == 1 {
			return true
		}
		if outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT &&
			abeTxOutputDescs[j].Value() == 1 {
			return false
		}
		// Part II-II [ (crypto.PrivacyLevelPseudonymCT,*) (crypto.PrivacyLevelPseudonym,*) ]
		if outputIAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT &&
			outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			return true
		}
		if outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT &&
			outputIAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			return false
		}

		return false
	})

	transferTxMsgTemplate, err := abecryptox.CreateTransferTxMsgTemplateByKeys(TxVersionCTAUT, abeTxInputDescs, abeTxOutputDescs, txRequestDesc.TxFee, txRequestDesc.TxMemo)
	if err != nil {
		return nil, nil, err
	}

	transferTxMsg, err := abecryptox.TransferTxGenByKeys(abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)
	if err != nil {
		return nil, nil, err
	}

	// CT-AUT
	transferTxMsg.AutWitness = autWitness

	buf := bytes.NewBuffer(make([]byte, 0, transferTxMsg.SerializeSizeFull()))
	err = transferTxMsg.SerializeFull(buf)
	if err != nil {
		return nil, nil, err
	}

	trTxId := TxId(transferTxMsg.TxId())

	return buf.Bytes(), &trTxId, nil
}

func CTAUTIdentifierKey(txID string) (res [ctaut.CTAUTIdentifierLength]byte, err error) {
	txHash, err := chainhash.NewHashFromStr(txID)
	if err != nil {
		return res, err
	}
	copy(res[:], txHash[:])
	return res, nil

}
