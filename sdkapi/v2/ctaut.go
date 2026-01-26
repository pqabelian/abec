package v2

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/pqabelian/abec/abecryptox"
	"github.com/pqabelian/abec/abecryptox/abecryptoxkey"
	"github.com/pqabelian/abec/chainhash"
	ctautapi "github.com/pqabelian/abec/ctaut/api"
	ctautwire "github.com/pqabelian/abec/ctaut/wire"
	"github.com/pqabelian/abec/wire"
)

const TxVersionForCTAUT = wire.TxVersion_Height_464000_Aconcagua
const AutScriptVersion = ctautwire.AutScriptVersion_1

type ExtAutScript = ctautapi.ExtAutScript

type AutScriptType = ctautapi.AutScriptType

const (
	AutScriptTypeRegistration   AutScriptType = ctautapi.AutScriptTypeRegistration
	AutScriptTypeReRegistration AutScriptType = ctautapi.AutScriptTypeReRegistration
	AutScriptTypeMint           AutScriptType = ctautapi.AutScriptTypeMint
	AutScriptTypeTransfer       AutScriptType = ctautapi.AutScriptTypeTransfer
	AutScriptTypeBurn           AutScriptType = ctautapi.AutScriptTypeBurn
)

type AutPrivacyType = ctautapi.AutPrivacyType

const (
	AutPrivacyTypeUnlimited     AutPrivacyType = ctautapi.AutPrivacyTypeUnlimited
	AutPrivacyTypeLimitedPublic AutPrivacyType = ctautapi.AutPrivacyTypeLimitedPublic
	AutPrivacyTypeLimitedHidden AutPrivacyType = ctautapi.AutPrivacyTypeLimitedHidden
)

type AutId = ctautapi.AutId

func NewAutId(autIdentifier string) (AutId, error) {
	hash, err := chainhash.NewHashFromStr(autIdentifier)
	if err != nil {
		return chainhash.InvalidHash, errors.New("invalid identifier")
	}
	return *hash, nil
}

type AutScript = ctautapi.AutScript
type HostOutPoint = ctautapi.HostOutPoint

func NewHostOutPoint(txHash string, index uint8) (*HostOutPoint, error) {
	hash, err := chainhash.NewHashFromStr(txHash)
	if err != nil {
		return nil, err
	}
	return &HostOutPoint{
		TxHash: *hash,
		Index:  index,
	}, nil
}

type Metadata = ctautapi.AutMetadata
type AutIssuer = ctautapi.AutIssuer

func NewAutIssuerFromCoinAddress(coinAddress []byte) *AutIssuer {
	return ctautapi.NewAutIssuerFromCoinAddress(coinAddress)
}

type CTAUTRegisterScript = ctautapi.RegistrationScript

func NewRegistrationScript(
	version uint32,
	ctAutName []byte, ctAutSymbol []byte, baseUnitName []byte, subUnitName []byte, unitScale uint64,
	ctAutMemo []byte, plannedTotalSupply uint64,
	issuerCoinAddresses [][]byte, reregistrationExpireHeight int32, reregisterThreshold uint8, mintThreshold uint8,
	privacyType AutPrivacyType,
	outStartIndex uint8, outAutRootTokenNum uint8,
	memo []byte,
) ([]byte, []byte, error) {
	issuers := make([]*ctautapi.AutIssuer, len(issuerCoinAddresses))
	for i := 0; i < len(issuers); i++ {
		issuers[i] = ctautapi.NewAutIssuerFromCoinAddress(issuerCoinAddresses[i])
	}
	script := ctautapi.NewRegistrationScript(
		version,
		ctAutName, ctAutSymbol, baseUnitName, subUnitName, unitScale,
		ctAutMemo, plannedTotalSupply,
		issuers, reregistrationExpireHeight, reregisterThreshold, mintThreshold,
		privacyType,
		outStartIndex, outAutRootTokenNum,
		memo)
	packagedAutScript, err := ctautapi.PackageAutScript(script)
	if err != nil {
		return nil, nil, err
	}

	return packagedAutScript, nil, nil
}

type CTAUTReRegisterScript = ctautapi.ReRegistrationScript

func NewReRegistrationScript(
	version uint32,
	ctAutIdentifier AutId,
	ctAutMemo []byte, plannedTotalSupply uint64,
	issuerCoinAddresses [][]byte, reregistrationExpireHeight int32, reregisterThreshold uint8, mintThreshold uint8,
	privacyType AutPrivacyType,
	inStartIndex uint8, inAutRootTokenNum uint8,
	outStartIndex uint8, outAutRootTokenNum uint8,
	memo []byte,
) ([]byte, []byte, error) {
	issuers := make([]*ctautapi.AutIssuer, len(issuerCoinAddresses))
	for i := 0; i < len(issuers); i++ {
		issuers[i] = ctautapi.NewAutIssuerFromCoinAddress(issuerCoinAddresses[i])
	}
	script := ctautapi.NewReRegistrationScript(
		version,
		ctAutIdentifier,
		ctAutMemo, plannedTotalSupply,
		issuers, reregistrationExpireHeight, reregisterThreshold, mintThreshold,
		privacyType,
		inStartIndex, inAutRootTokenNum,
		outStartIndex, outAutRootTokenNum,
		memo,
	)
	packagedAutScript, err := ctautapi.PackageAutScript(script)
	if err != nil {
		return nil, nil, err
	}

	return packagedAutScript, nil, nil
}

type CTAUTMintScript = ctautapi.MintScript

func NewMintScript(
	version uint32,
	ctAutIdentifier AutId,
	vin uint64,
	inStartIndex uint8, inAutRootTokenNum uint8,
	outStartIndex uint8, autTxOutputDescs []*AutTxOutputDesc, /*outCTAutTokenNum uint8, outPlainAutTokenNum uint8,*/
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

	autCoinbaseTx, err := abecryptox.AutCoinbaseTxGen(AutScriptVersion, vin, outputDescs)
	if err != nil {
		return nil, nil, err
	}

	valueScripts := make([][]byte, len(autCoinbaseTx.TxOuts))
	for i, autTxo := range autCoinbaseTx.TxOuts {
		valueScripts[i], err = autTxo.Serialize()
		if err != nil {
			return nil, nil, err
		}
	}

	witnessHash := ctautwire.AutWitnessHash(autCoinbaseTx.TxWitness)
	script := ctautapi.NewMintScript(
		version,
		ctAutIdentifier,
		vin,
		inStartIndex, inAutRootTokenNum,
		outStartIndex, outCTAutTokenNum, outPlainAutTokenNum,
		valueScripts,
		memo,
		witnessHash)
	packagedAutScript, err := ctautapi.PackageAutScript(script)
	if err != nil {
		return nil, nil, err
	}
	return packagedAutScript, autCoinbaseTx.TxWitness, nil
}

type CTAUTTransferScript = ctautapi.TransferScript

func NewTransferScript(
	version uint32,
	ctAutIdentifier AutId,
	inStartIndex uint8, autInputDescs []*AutTxInputDesc, /* inHiddenAutTokenNum uint8, inPublicAutTokenNum uint8,*/
	outStartIndex uint8, autOutputDescs []*AutTxOutputDesc, /* outHiddenAutTokenNum uint8, outPublicAutTokenNum uint8*/
	memo []byte,
) ([]byte, []byte, error) {

	var inCTAutTokenNum uint8 = 0
	var inPlainAutTokenNum uint8 = 0
	inputDescs := make([]*abecryptox.AutTxInputDesc, len(autInputDescs))
	for i := 0; i < len(autInputDescs); i++ {
		autInputDesc := autInputDescs[i]
		autTxo := &ctautwire.AutTxo{}
		err := autTxo.Deserialize(autInputDesc.ValueScript)
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

	autTransferTx, err := abecryptox.AutTransferTxGen(AutScriptVersion, inputDescs, outputDescs)
	if err != nil {
		return nil, nil, err
	}

	//fmt.Printf("version %d\n", autTransferTx.Version)
	//for i := 0; i < len(autTransferTx.TxIns); i++ {
	//	fmt.Printf("\t input[%d].version %d\n", i, autTransferTx.TxIns[i].Version)
	//	digest := md5.Sum(autTransferTx.TxIns[i].TxoScript)
	//	fmt.Printf("\t input[%d].txoscript %s\n", i, hex.EncodeToString(digest[:]))
	//}
	//for i := 0; i < len(autTransferTx.TxOuts); i++ {
	//	fmt.Printf("\t output[%d].version %d\n", i, autTransferTx.TxOuts[i].Version)
	//	digest := md5.Sum(autTransferTx.TxOuts[i].TxoScript)
	//	fmt.Printf("\t output[%d].txoscript %s\n", i, hex.EncodeToString(digest[:]))
	//}

	// TODO would be remove
	err = abecryptox.AutTransferTxVerify(autTransferTx)
	if err != nil {
		panic(err)
		//return fmt.Errorf(`transaction %s try to transfer tokens but the witness verfied fail with %s`,
		//	tx.Hash(), err)
	}

	valueScripts := make([][]byte, len(autTransferTx.TxOuts))
	for i, autTxo := range autTransferTx.TxOuts {
		valueScripts[i], err = autTxo.Serialize()
		if err != nil {
			return nil, nil, err
		}
	}
	witnessHash := ctautwire.AutWitnessHash(autTransferTx.TxWitness)

	script := ctautapi.NewTransferScript(
		version,
		ctAutIdentifier,
		inStartIndex, inCTAutTokenNum, inPlainAutTokenNum,
		outStartIndex, outCTAutTokenNum, outPlainAutTokenNum,
		valueScripts,
		memo,
		witnessHash,
	)
	packagedAutScript, err := ctautapi.PackageAutScript(script)
	if err != nil {
		return nil, nil, err
	}
	return packagedAutScript, autTransferTx.TxWitness, nil
}

type CTAUTBurnScript = ctautapi.BurnScript

func NewBurnScript(
	version uint32,
	ctAutIdentifier AutId,
	inStartIndex uint8, autInputDescs []*AutTxInputDesc, /* inHiddenAutTokenNum uint8, inPublicAutTokenNum uint8,*/
	outStartIndex uint8, autOutputDescs []*AutTxOutputDesc, /* outHiddenAutTokenNum uint8, outPublicAutTokenNum uint8*/
	memo []byte,
) ([]byte, []byte, error) {
	var inCTAutTokenNum uint8 = 0
	var inPlainAutTokenNum uint8 = 0
	inputDescs := make([]*abecryptox.AutTxInputDesc, len(autInputDescs))
	for i := 0; i < len(autInputDescs); i++ {
		autInputDesc := autInputDescs[i]
		autTxo := &ctautwire.AutTxo{}
		err := autTxo.Deserialize(autInputDesc.ValueScript)
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

	autTransferTx, err := abecryptox.AutTransferTxGen(AutScriptVersion, inputDescs, outputDescs)
	if err != nil {
		return nil, nil, err
	}

	// TODO would be remove
	err = abecryptox.AutTransferTxVerify(autTransferTx)
	if err != nil {
		panic(err)
	}

	valueScripts := make([][]byte, len(autTransferTx.TxOuts))
	for i, autTxo := range autTransferTx.TxOuts {
		valueScripts[i], err = autTxo.Serialize()
		if err != nil {
			return nil, nil, err
		}
	}
	witnessHash := ctautwire.AutWitnessHash(autTransferTx.TxWitness)

	script := ctautapi.NewBurnScript(
		version,
		ctAutIdentifier,
		inStartIndex, inCTAutTokenNum, inPlainAutTokenNum,
		outStartIndex, outCTAutTokenNum, outPlainAutTokenNum,
		valueScripts,
		memo,
		witnessHash,
	)
	packagedAutScript, err := ctautapi.PackageAutScript(script)
	if err != nil {
		return nil, nil, err
	}
	return packagedAutScript, autTransferTx.TxWitness, nil
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
	err := autTxo.Deserialize(valueScript)
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

func ExtractAutScriptFromHostTx(serializedTx []byte) (*ExtAutScript, error) {
	msgTx := &wire.MsgTxAbe{}
	err := msgTx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		return nil, err
	}

	extAutScript, err := ctautapi.DetectAndAssembleExtAutScriptFromHostTx(msgTx)
	if err != nil {
		return nil, err
	}

	return extAutScript, nil
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
			outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			if abeTxOutputDescs[i].Value() == 1 && abeTxOutputDescs[j].Value() != 1 {
				return true
			}
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

	transferTxMsgTemplate, err := abecryptox.CreateTransferTxMsgTemplateByRootSeeds(TxVersionForCTAUT, abeTxInputDescs, abeTxOutputDescs, txRequestDesc.TxFee, txRequestDesc.TxMemo)
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
			outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			if abeTxOutputDescs[i].Value() == 1 && abeTxOutputDescs[j].Value() != 1 {
				return true
			}
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

	transferTxMsgTemplate, err := abecryptox.CreateTransferTxMsgTemplateByKeys(TxVersionForCTAUT, abeTxInputDescs, abeTxOutputDescs, txRequestDesc.TxFee, txRequestDesc.TxMemo)
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
