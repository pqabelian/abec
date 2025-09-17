package abecryptox

import (
	"fmt"

	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/ctaut/wire"
	"github.com/cryptosuite/pqringctx/pqringctxapi"
)

// AutTxoType is defined for the types of AutTxo, which is actually pqringctxapi.CtxTxoType,
// since it will also be passed to underlying crypto-scheme.
type AutTxoType = pqringctxapi.CtxTxoType

const (
	AutTxoTypeHidden = pqringctxapi.CtxTxoTypeHidden
	AutTxoTypePublic = pqringctxapi.CtxTxoTypePublic
)

// // abecryptox -> abepqringctx -> pqringctx

// pqringctxAutCoinbaseTxGen generates a new AutCoinbaseTx,
// for the input (txVersion uint32, vin uint64, autTxOutputDescs []*AutTxOutputDesc).
func pqringctxAutCoinbaseTxGen(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	txVersion uint32, vin uint64, autTxOutputDescs []*AutTxOutputDesc) (*wire.AutCoinbaseTx, error) {
	// just redundant double check
	cryptoSchemeFromTxVersion, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return nil, err
	}
	if cryptoSchemeFromTxVersion != cryptoScheme {
		return nil, fmt.Errorf("pqringctxAutCoinbaseTxGen: the input cryptoScheme is different from that implied by txVersion")
	}

	//	parse AutTxOutputDesc to pqringctx.CtxTxOutputDesc
	ctxTxOutputDesc := make([]*pqringctxapi.CtxTxOutputDesc, len(autTxOutputDescs))
	for j := 0; j < len(autTxOutputDescs); j++ {
		ctxTxOutputDesc[j] = pqringctxapi.NewCtxTxOutputDesc(autTxOutputDescs[j].AutTxoType(), autTxOutputDescs[j].coinValuePublicKey, autTxOutputDescs[j].value)
	}

	// call the pqringctx.CtxCoinbaseTxGen
	ctxCoinbaseTx, err := pqringctxapi.CtxCoinbaseTxGen(pp, vin, ctxTxOutputDesc)
	if err != nil {
		return nil, err
	}

	// parse the pqringctx.CtxCoinbaseTxGen to wire.AutCoinbaseTx
	ctxTxos := pqringctxapi.GetCtxCoinbaseTxTxos(ctxCoinbaseTx)
	autTxos := make([]*wire.AutTxo, len(ctxTxos))
	for i := 0; i < len(ctxTxos); i++ {
		serializedCtxTxo, err := pqringctxapi.SerializeCtxTxo(pp, ctxTxos[i])
		if err != nil {
			return nil, err
		}
		autTxos[i] = &wire.AutTxo{
			Version:   txVersion,
			TxoScript: serializedCtxTxo,
		}
	}

	// witness must be associated with Tx, so it does not need to contain cryptoScheme or TxVersion.
	ctxCbTxWitness := pqringctxapi.GetCtxCoinbaseTxTxWitness(ctxCoinbaseTx)
	autTxWitness, err := pqringctxapi.SerializeCtxTxWitnessCbTx(pp, ctxCbTxWitness)
	if err != nil {
		return nil, err
	}

	autCoinbaseTx := &wire.AutCoinbaseTx{
		Version:   txVersion,
		Vin:       vin,
		TxOuts:    autTxos,
		TxWitness: autTxWitness,
	}

	return autCoinbaseTx, nil
}

// pqringctxAutCoinbaseTxVerify verify the input autCoinbaseTx *wire.AutCoinbaseTx.
// The caller needs to guarantee the well-form of the input autCoinbaseTx *wire.AutCoinbaseTx, such as the TxOuts.
// This function only checks the balance proof, by calling the crypto-scheme.
func pqringctxAutCoinbaseTxVerify(pp *pqringctxapi.PublicParameter, autCoinbaseTx *wire.AutCoinbaseTx) error {
	if autCoinbaseTx == nil {
		return fmt.Errorf("pqringctxAutCoinbaseTxVerify: the input autCoinbaseTx is nil")
	}
	if len(autCoinbaseTx.TxOuts) <= 0 {
		return fmt.Errorf("pqringctxAutCoinbaseTxVerify: autCoinbaseTx.TxOuts is nil/empty")
	}

	var err error

	vin := autCoinbaseTx.Vin

	ctxTxos := make([]pqringctxapi.CtxTxo, len(autCoinbaseTx.TxOuts))
	for j := 0; j < len(autCoinbaseTx.TxOuts); j++ {
		if autCoinbaseTx.TxOuts[j].Version != autCoinbaseTx.Version {
			return fmt.Errorf("pqringctxAutCoinbaseTxVerify: autCoinbaseTx.TxOuts[%d].Version (%d) != autCoinbaseTx.Version (%d)",
				j, autCoinbaseTx.TxOuts[j].Version, autCoinbaseTx.Version)
		}

		ctxTxos[j], err = pqringctxapi.DeserializeCtxTxo(pp, autCoinbaseTx.TxOuts[j].TxoScript)
		if err != nil {
			return err
		}
	}

	ctxTxWitness, err := pqringctxapi.DeserializeCtxTxWitnessCbTx(pp, autCoinbaseTx.TxWitness)
	if err != nil {
		return err
	}

	ctxCoinbaseTx := pqringctxapi.NewCtxCoinbaseTx(vin, ctxTxos, ctxTxWitness)

	err = pqringctxapi.CtxCoinbaseTxVerify(pp, ctxCoinbaseTx)
	if err != nil {
		return err
	}

	return nil
}

// pqringctxAutTransferTxGen generates a new AutTransferTx,
// for the input (txVersion uint32, autTxInputDescs []*AutTxInputDesc, autTxOutputDescs []*AutTxOutputDesc).
// The parameter cryptoScheme here is obtained by the caller from TxVersion, which causes this function is called.
// Now it is redundant at this moment and works for ony double-check.
func pqringctxAutTransferTxGen(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	txVersion uint32, autTxInputDescs []*AutTxInputDesc, autTxOutputDescs []*AutTxOutputDesc) (*wire.AutTransferTx, error) {

	// just redundant double check
	cryptoSchemeFromTxVersion, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return nil, err
	}
	if cryptoSchemeFromTxVersion != cryptoScheme {
		return nil, fmt.Errorf("pqringctxAutTransferTxGen: the input cryptoScheme is different from that implied by transferTxMsgTemplate.Version")
	}

	inputNum := len(autTxInputDescs)
	outputNum := len(autTxOutputDescs)

	if inputNum == 0 || outputNum == 0 {
		return nil, fmt.Errorf("pqringctxAutTransferTxGen: neither the input autTxInputDescs or autTxOutputDescs could be empty")
	}

	// xtTxInputDescs
	ctxTxInputDescs := make([]*pqringctxapi.CtxTxInputDesc, inputNum)
	for i := 0; i < inputNum; i++ {
		if autTxInputDescs[i].autTxo.Version != txVersion {
			//	The caller is attempting to spend the AutTxos generated by Txs with different versions.
			//	Here we need to hard code to accept only the expected cases.
			return nil, fmt.Errorf("pqringctxAutTransferTxGen: attempting to spend AuTtxos created by transactions with differnet versions, but the case is out of the allowed ones")
		}

		// ctxTxo
		ctxTxo, err := pqringctxapi.DeserializeCtxTxo(pp, autTxInputDescs[i].autTxo.TxoScript)
		if err != nil {
			return nil, err
		}

		//	coinValuePublicKey, coinValueSecretKey
		if ctxTxo.CtxTxoType() == pqringctxapi.CtxTxoTypeHidden {
			if len(autTxInputDescs[i].coinValuePublicKey) == 0 {
				// only fore CtxTxoTypePublic, the coinValuePublicKey could be nil.
				return nil, fmt.Errorf("pqringctxAutTransferTxGen: the autTxInputDescs[%d].autTxo is CtxTxoTypeHidden, but the coinValuePublicKey is nil", i)
			}

			if len(autTxInputDescs[i].coinValueSecretKey) == 0 {
				// only fore CtxTxoTypePublic, the coinValueSecretKey could be nil.
				return nil, fmt.Errorf("pqringctxAutTransferTxGen: the autTxInputDescs[%d].autTxo is CtxTxoTypeHidden, but the coinValueSecretKey is nil", i)
			}
		}

		ctxTxInputDescs[i] = pqringctxapi.NewCtxTxInputDesc(ctxTxo, autTxInputDescs[i].coinValuePublicKey, autTxInputDescs[i].coinValueSecretKey, autTxInputDescs[i].value)
	}

	//	ctxTxOutputDescs
	ctxTxOutputDescs := make([]*pqringctxapi.CtxTxOutputDesc, outputNum)
	for j := 0; j < outputNum; j++ {
		if autTxOutputDescs[j].autTxoType == AutTxoTypeHidden {
			if len(autTxOutputDescs[j].coinValuePublicKey) == 0 {
				// only fore AutTxoTypeHidden, the coinValuePublicKey could be nil.
				return nil, fmt.Errorf("pqringctxAutTransferTxGen: the autTxOutputDescs[%d].autTxoType is AutTxoTypeHidden, but the coinValuePublicKey is nil", j)
			}
		}

		ctxTxOutputDescs[j] = pqringctxapi.NewCtxTxOutputDesc(autTxOutputDescs[j].autTxoType, autTxOutputDescs[j].coinValuePublicKey, autTxOutputDescs[j].value)
	}

	//	call the crypto scheme
	ctxTransferTx, err := pqringctxapi.CtxTransferTxGen(pp, ctxTxInputDescs, ctxTxOutputDescs)
	if err != nil {
		return nil, err
	}

	//	Set the txInputs
	//	As the underlying crypto-scheme will not change this part, it can be set directly using the autTxInputDescs
	autTxIns := make([]*wire.AutTxo, inputNum)
	for i := 0; i < inputNum; i++ {
		autTxIns[i] = autTxInputDescs[i].autTxo
	}

	// Set the TxOuts
	ctxTxos := pqringctxapi.GetCtxTransferTxTxos(ctxTransferTx)
	autTxos := make([]*wire.AutTxo, len(ctxTxos))
	for j := 0; j < len(ctxTxos); j++ {
		serializedCtxTxo, err := pqringctxapi.SerializeCtxTxo(pp, ctxTxos[j])
		if err != nil {
			return nil, err
		}
		autTxos[j] = &wire.AutTxo{
			Version:   txVersion,
			TxoScript: serializedCtxTxo,
		}
	}

	// witness must be associated with Tx, so it does not need to contain cryptoScheme or TxVersion.
	ctxTrTxWitness := pqringctxapi.GetCtxTransferTxTxWitness(ctxTransferTx)
	autTxWitness, err := pqringctxapi.SerializeCtxTxWitnessTrTx(pp, ctxTrTxWitness)
	if err != nil {
		return nil, err
	}

	autTransferTx := &wire.AutTransferTx{
		Version:   txVersion,
		TxIns:     autTxIns,
		TxOuts:    autTxos,
		TxWitness: autTxWitness,
	}

	return autTransferTx, nil
}

// pqringctxAutTransferTxVerify verify the input autTransferTx *wire.AutTransferTx.
// The caller needs to guarantee the well-form of the input autTransferTx *wire.AutTransferTx, such as the TxOuts.
// This function only checks the balance proof, by calling the crypto-scheme.
func pqringctxAutTransferTxVerify(pp *pqringctxapi.PublicParameter, autTransferTx *wire.AutTransferTx) error {
	if autTransferTx == nil {
		return fmt.Errorf("pqringctxAutTransferTxVerify: the input transferTx is empty")
	}

	inputNum := len(autTransferTx.TxIns)
	outputNum := len(autTransferTx.TxOuts)
	if inputNum <= 0 {
		return fmt.Errorf("pqringctxAutTransferTxVerify: the inputNum is 0")
	}
	if outputNum <= 0 {
		return fmt.Errorf("pqringctxAutTransferTxVerify: the outputNum is 0")
	}

	var err error
	//	txInputs
	ctxTxInputs := make([]pqringctxapi.CtxTxo, inputNum)
	for i := 0; i < inputNum; i++ {
		if autTransferTx.TxIns[i].Version != autTransferTx.Version {
			//	not in the allowed cases
			return fmt.Errorf("pqringctxAutTransferTxVerify: (autTransferTx.TxIns[%d].Version (%d), autTransferTx.Version (%d)) is not allowed",
				i, autTransferTx.TxIns[i].Version, autTransferTx.Version)
		}
		ctxTxInputs[i], err = pqringctxapi.DeserializeCtxTxo(pp, autTransferTx.TxIns[i].TxoScript)
		if err != nil {
			return err
		}
	}

	//	txos
	ctxTxos := make([]pqringctxapi.CtxTxo, outputNum)
	for j := 0; j < outputNum; j++ {
		if autTransferTx.TxOuts[j].Version != autTransferTx.Version {
			return fmt.Errorf("pqringctxTransferTxVerify: transferTx.TxOuts[%d].Version (%d) != transferTx.Version (%d)",
				j, autTransferTx.TxOuts[j].Version, autTransferTx.Version)
			//	The output Txos of a transaction should have the same version as the transaction.
		}

		ctxTxos[j], err = pqringctxapi.DeserializeCtxTxo(pp, autTransferTx.TxOuts[j].TxoScript)
		if err != nil {
			return err
		}
	}

	//	TxWitness
	ctxTxWitness, err := pqringctxapi.DeserializeCtxTxWitnessTrTx(pp, autTransferTx.TxWitness)
	if err != nil {
		return err
	}

	ctxTransferTx := pqringctxapi.NewCtxTransferTx(ctxTxInputs, ctxTxos, ctxTxWitness)

	// call the crypto scheme's verify algorithm
	err = pqringctxapi.CtxTransferTxVerify(pp, ctxTransferTx)
	if err != nil {
		return err
	}

	return nil
}

// helper functions	begin
//	helper functions	end

//	APIs for Txos	begin

// pqringctxGetAutTxoType returns the AutTxoType of the input *wire.AutTxo.
func pqringctxGetAutTxoType(pp *pqringctxapi.PublicParameter, autTxo *wire.AutTxo) (AutTxoType, error) {
	ctxTxo, err := pqringctxapi.DeserializeCtxTxo(pp, autTxo.TxoScript)
	if err != nil {
		return pqringctxapi.CtxTxoTypeHidden, err
	}

	return ctxTxo.CtxTxoType(), nil
}

// pqringctxGetAutTxoScriptSize returns the TxoScript size for the input CtxTxoType.
func pqringctxGetAutTxoScriptSize(pp *pqringctxapi.PublicParameter, autTxoType AutTxoType) (int, error) {
	// Note that AutTxoType is defined to be CtxTxoType.
	return pqringctxapi.GetCtxTxoSerializeSizeByCtxTxoType(pp, autTxoType)
}

// pqringctxExtractValueFromAutTxo extracts the value of the input AutTxo,
// using the input (coinValuePublicKey, coinValueSecretKey).
func pqringctxExtractValueFromAutTxo(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	autTxo *wire.AutTxo, coinValuePublicKey []byte, coinValueSecretKey []byte) (value uint64, err error) {
	cryptoSchemeInTxo, err := abecryptoxparam.GetCryptoSchemeByTxVersion(autTxo.Version)
	if err != nil {
		return 0, err
	}

	if cryptoSchemeInTxo != cryptoScheme {
		return 0, fmt.Errorf("pqringctxExtractValueFromAutTxo: unmatched cryptoScheme for the input AutTxo")
	}

	// NOTE: As the abepqringctx-layer obtained CtxTxo (associated in CtxTransferTx/CtxCoinbaseTx)
	// and serialized it to AutTxo.TxoScript,
	// here abepqringctx-layer calls crypto-scheme using CtxTxo.
	ctxTxo, err := pqringctxapi.DeserializeCtxTxo(pp, autTxo.TxoScript)
	if err != nil {
		return 0, err
	}

	return pqringctxapi.ExtractValueFromCtxTxo(pp, ctxTxo, coinValuePublicKey, coinValueSecretKey)
}

//	APIs for Txos	end

// APIs for TxWitnesses	begin

// pqringctxGetAutCoinbaseTxWitnessSizeByDesc returns the AutCoinbaseTxWitnessSize,
// which depends on the number of AutTxoHidden.
func pqringctxGetAutCoinbaseTxWitnessSizeByDesc(pp *pqringctxapi.PublicParameter, outNumForHidden uint8) (int, error) {
	return pqringctxapi.GetCtxTxWitnessCbTxSerializeSizeByDesc(pp, outNumForHidden)
}

// pqringctxGetAutTransferTxWitnessSizeByDesc returns the size of AutTransferTxWitness,
// which depends on the description information (inNumForHidden uint8, outNumForHidden uint8, vPublic int64),
// where vPublic = (sum of public value for out) - (sum of public value for in).
func pqringctxGetAutTransferTxWitnessSizeByDesc(pp *pqringctxapi.PublicParameter, inNumForHidden uint8, outNumForHidden uint8, vPublic int64) (int, error) {
	return pqringctxapi.GetCtxTxWitnessTrTxSerializeSizeByDesc(pp, inNumForHidden, outNumForHidden, vPublic)
}

//	APIs for TxWitnesses	end
