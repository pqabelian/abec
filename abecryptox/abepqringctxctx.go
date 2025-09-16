package abecryptox

import (
	"fmt"

	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/ctaut/wire"
	"github.com/cryptosuite/pqringctx/pqringctxapi"
)

// CtxTxoType is defined for the types of CtxTxo.
type AutTxoType = pqringctxapi.CtxTxoType

const (
	AutTxoTypeHidden = pqringctxapi.CtxTxoTypeHidden
	AutTxoTypePublic = pqringctxapi.CtxTxoTypePublic
)

// // abecryptox -> abepqringctx -> pqringctx

// The caller needs to fill the Version, TxIns, TxFee, TxMemo fields for coinbaseTxMsgTemplate,
// this function will fill the TxOuts and TxWitness fields.
func pqringctxAutCoinbaseTxGen(pp *pqringctxapi.PublicParameter, txVersion uint32, vin uint64, autTxOutputDescs []*AutTxOutputDesc) (*wire.AutCoinbaseTx, error) {

	//	parse AbeTxOutputDesc to pqringctx.TxOutputDesc
	ctxTxOutputDesc := make([]*pqringctxapi.CtxTxOutputDesc, len(autTxOutputDescs))
	for j := 0; j < len(autTxOutputDescs); j++ {
		ctxTxOutputDesc[j] = pqringctxapi.NewCtxTxOutputDesc(autTxOutputDescs[j].AutTxoType(), autTxOutputDescs[j].coinValuePublicKey, autTxOutputDescs[j].value)
	}

	// call the pqringctx.CoinbaseTxGen
	//	vin is set in coinbaseTxMsgTemplate.TxFee
	ctxCoinbaseTx, err := pqringctxapi.CtxCoinbaseTxGen(pp, vin, ctxTxOutputDesc)
	if err != nil {
		return nil, err
	}

	// parse the pqringctx.CoinbaseTx to wire.TxAbe
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
	serializedCtxCbTxWitness, err := pqringctxapi.SerializeCtxTxWitnessCbTx(pp, ctxCbTxWitness)
	if err != nil {
		return nil, err
	}
	autTxWitness := serializedCtxCbTxWitness

	autCoinbaseTx := &wire.AutCoinbaseTx{
		Version:   txVersion,
		Vin:       vin,
		TxOuts:    autTxos,
		TxWitness: autTxWitness,
	}

	return autCoinbaseTx, nil
}

// pqringctxCoinbaseTxVerify verify the input coinbaseTx *wire.MsgTxAbe.
// The caller needs to guarantee the well-form of the input coinbaseTx *wire.MsgTxAbe, such as the TxIns.
// This function only checks the balance proof, by calling the crypto-scheme.
func pqringctxAutCoinbaseTxVerify(pp *pqringctxapi.PublicParameter, autCoinbaseTx *wire.AutCoinbaseTx) error {
	if autCoinbaseTx == nil {
		return fmt.Errorf("pqringctxCoinbaseTxVerify: the input coinbaseTx is nil")
	}
	if len(autCoinbaseTx.TxOuts) <= 0 {
		return fmt.Errorf("pqringctxCoinbaseTxVerify: coinbaseTx.TxOuts is nil/empty")
	}

	var err error

	vin := autCoinbaseTx.Vin

	ctxTxos := make([]pqringctxapi.CtxTxo, len(autCoinbaseTx.TxOuts))
	for j := 0; j < len(autCoinbaseTx.TxOuts); j++ {
		if autCoinbaseTx.TxOuts[j].Version != autCoinbaseTx.Version {
			return fmt.Errorf("pqringctxCoinbaseTxVerify: coinbaseTx.TxOuts[%d].Version (%d) != coinbaseTx.Version (%d)",
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
	//if bl == false {
	//	return false, nil
	//}

	return nil
}

// pqringctxTransferTxGenByKeys generates a MsgTxAbe,
// by filling TxIns[].serialNumber，Txos, and TxWitness of the input transferTxMsgTemplate.
// The caller needs to fill the Version, TxIns[].PreviousOutPointRing, TxFee, TxMemo fields of transferTxMsgTemplate.
// This function will fill the TxIns[].serialNumber，Txos, and TxWitness of the input transferTxMsgTemplate, and return it as the result.
// The parameter cryptoScheme here is obtained by the caller from TxVersion, which causes this function is called.
// Now it is redundant at this moment and works for ony double-check.
// In the future, when the version of input ring is different from the ring of TxVersion/TxoVersion,
// the two corresponding cryptoSchemes will be extracted here and further decides the TxGen algorithms.
// Refer to wire.param for the details.
// reviewed on 2023.12.21
// todo: to review
// todo: review CryptoValueSecretKeyParse
func pqringctxAutTransferTxGen(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	txVersion uint32, autTxInputDescs []*AutTxInputDesc, autTxOutputDescs []*AutTxOutputDesc) (*wire.AutTransferTx, error) {
	// just redundant double check
	cryptoSchemeFromTxVersion, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return nil, err
	}
	if cryptoSchemeFromTxVersion != cryptoScheme {
		return nil, fmt.Errorf("pqringctxTransferTxGen: the input cryptoScheme is different from that implied by transferTxMsgTemplate.Version")
	}

	inputNum := len(autTxInputDescs)
	outputNum := len(autTxOutputDescs)

	if inputNum == 0 || outputNum == 0 {
		return nil, fmt.Errorf("pqringctxTransferTxGen: neither the input abeTxInputDescs or abeTxOutputDescs could be empty")
	}

	// cryptoTxInputDescs
	ctxTxInputDescs := make([]*pqringctxapi.CtxTxInputDesc, inputNum)
	for i := 0; i < inputNum; i++ {
		if autTxInputDescs[i].autTxo.Version != txVersion {
			//	the transferTxMsgTemplate is attempting to spend the coins generated by Txs with different versions.
			//	Here we need to hard code to accept only the expected cases.
			return nil, fmt.Errorf("pqringctxTransferTxGen: the transferTxMsgTemplate is attempting to spend coins created by transactions with differnet versions, but the case is out of the allowed ones")
		}

		// ctxTxo
		ctxTxo, err := pqringctxapi.DeserializeCtxTxo(pp, autTxInputDescs[i].autTxo.TxoScript)
		if err != nil {
			return nil, err
		}

		//	coinValuePublicKey, coinValueSecretKey
		if ctxTxo.CtxTxoType() == pqringctxapi.CtxTxoTypeHidden {
			if len(autTxInputDescs[i].coinValuePublicKey) == 0 {
				// only when the privacyLevelInAddress is PrivacyLevelPSEUDONYM, the extracted coinValuePublicKey from the cryptoAddress could be nil.
				return nil, fmt.Errorf("pqringctxTransferTxGen: the abeTxInputDescs[%d].[%d]-th Txo's privacy-level is not PrivacyLevelPSEUDONYM, but the coinValuePublicKey is nil", i)
			}

			if len(autTxInputDescs[i].coinValueSecretKey) == 0 {
				// only when the privacyLevelInAddress is PrivacyLevelPSEUDONYM, the extracted coinValuePublicKey from the cryptoAddress could be nil.
				return nil, fmt.Errorf("pqringctxTransferTxGen: the abeTxInputDescs[%d].[%d]-th Txo's privacy-level is not PrivacyLevelPSEUDONYM, but the coinValuePublicKey is nil", i)
			}
		}

		ctxTxInputDescs[i] = pqringctxapi.NewCtxTxInputDesc(ctxTxo, autTxInputDescs[i].coinValuePublicKey, autTxInputDescs[i].coinValueSecretKey, autTxInputDescs[i].value)
	}

	//	cryptoTxOutputDescs
	ctxTxOutputDescs := make([]*pqringctxapi.CtxTxOutputDesc, outputNum)
	for j := 0; j < outputNum; j++ {
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

// pqringctxTransferTxVerify verifies wire.MsgTxAbe.
func pqringctxAutTransferTxVerify(pp *pqringctxapi.PublicParameter, autTransferTx *wire.AutTransferTx) error {
	if autTransferTx == nil {
		return fmt.Errorf("pqringctxTransferTxVerify: the input transferTx is empty")
	}

	inputNum := len(autTransferTx.TxIns)
	outputNum := len(autTransferTx.TxOuts)
	if inputNum <= 0 {
		return fmt.Errorf("pqringctxTransferTxVerify: the inputNum is 0")
	}
	if outputNum <= 0 {
		return fmt.Errorf("pqringctxTransferTxVerify: the outputNum is 0")
	}

	var err error
	//	txInputs
	ctxTxInputs := make([]pqringctxapi.CtxTxo, inputNum)
	for i := 0; i < inputNum; i++ {
		if autTransferTx.TxIns[i].Version != autTransferTx.Version {
			//	not in the allowed cases
			return fmt.Errorf("pqringctxTransferTxVerify: transferTx.TxIns[%d].PreviousOutPointRing.Version (%d) is out of design", i, autTransferTx.Version)
		}
		ctxTxInputs[i], err = pqringctxapi.DeserializeCtxTxo(pp, autTransferTx.TxIns[i].TxoScript) //	Note that pqringctx can deserialize the TxoScript generated by pqringct.
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

// pqringctxGetTxoPrivacyLevel returns the PrivacyLevel of the input wire.TxOutAbe.
// reviewed on 2024.01.04
func pqringctxGetAutTxoType(pp *pqringctxapi.PublicParameter, autTxo *wire.AutTxo) (AutTxoType, error) {
	ctxTxo, err := pqringctxapi.DeserializeCtxTxo(pp, autTxo.TxoScript)
	if err != nil {
		return pqringctxapi.CtxTxoTypeHidden, err
	}

	return ctxTxo.CtxTxoType(), nil
}

// pqringctxGetAutTxoSerializeSize returns the TxoSerializeSize for the input coinAddress.
func pqringctxGetAutTxoScriptSize(pp *pqringctxapi.PublicParameter, ctxTxoType pqringctxapi.CtxTxoType) (int, error) {
	return pqringctxapi.GetCtxTxoSerializeSize(pp, ctxTxoType)
}

// pqringctxTxoCoinReceiveByKeys checks whether the input abeTxo *wire.TxOutAbe belongs to the owner of the input cryptoAddress, and if true,
// it extracts the value of abeTxo using the input cryptoValueSecretKey (if it indeed corresponds to the cryptoAddress).
func pqringctxExtractValueFromAutTxo(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	autTxo *wire.AutTxo, coinValuePublicKey []byte, coinValueSecretKey []byte) (value uint64, err error) {
	cryptoSchemeInTxo, err := abecryptoxparam.GetCryptoSchemeByTxVersion(autTxo.Version)
	if err != nil {
		return 0, err
	}

	if cryptoSchemeInTxo != cryptoScheme {
		return 0, fmt.Errorf("pqringctxTxoCoinReceiveByKeys: unmatched cryptoScheme for the input Txo")
	}

	//	NOTE: As the abepqringctx-layer obtained TxoMLP (associated in crypto-TransferTx/CoinbaseTx) and serialized it to abeTxo.TxoScript,
	//	here abepqringctx-layer calls crypto-scheme using TxoMLP.
	ctxTxo, err := pqringctxapi.DeserializeCtxTxo(pp, autTxo.TxoScript)
	if err != nil {
		return 0, err
	}

	return pqringctxapi.ExtractValueFromCtxTxo(pp, ctxTxo, coinValuePublicKey, coinValueSecretKey)
}

//	APIs for Txos	end

// APIs for TxWitnesses	begin

// pqringctxGetAutCoinbaseTxWitnessSerializeSizeByDesc returns the TxWitnessCbTxSerializeSize for a CbTx,
// which takes the input cryptoAddressListPayTo[] as the cryptoAddressList for the output Txos.
// todo: review
func pqringctxGetAutCoinbaseTxWitnessSerializeSizeByDesc(pp *pqringctxapi.PublicParameter, outNumForHidden uint8) (int, error) {
	return pqringctxapi.GetCtxTxWitnessCbTxSerializeSizeByDesc(pp, outNumForHidden)
}

// todo: vPublic = (sum of public value for out) - (sum of public value for in)
func pqringctxGetAutTransferTxWitnessSerializeSizeByDesc(pp *pqringctxapi.PublicParameter, inNumForHidden uint8, outNumForHidden uint8, vPublic int64) (int, error) {
	return pqringctxapi.GetCtxTxWitnessTrTxSerializeSizeByDesc(pp, inNumForHidden, outNumForHidden, vPublic)
}

//	APIs for TxWitnesses	end
