package abepqringct

import (
	"encoding/binary"
	"errors"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/wire"
	"github.com/cryptosuite/pqringct"
)

var cryptoPP *pqringct.PublicParameter = pqringct.DefaultPP

//	todo:
func GetMasterPublicKeyLen(version uint32) uint32 {

	return 1
}

type MasterPublicKey interface {
	SerializeSize() uint32
	Serialize() []byte
	Deserialize([]byte) error
}

type MasterSecretViewKey interface {
	SerializeSize() uint32
	Serialize() []byte
	Deserialize([]byte) error
}

type MasterSecretSignKey interface {
	SerializeSize() uint32
	Serialize() []byte
	Deserialize([]byte) error
}

type AbeTxOutDesc struct {
	serializedMasterPublicKey []byte
	value                     uint64
}

func NewAbeTxOutDesc(serializedMpk []byte, value uint64) *AbeTxOutDesc {
	return &AbeTxOutDesc{
		serializedMpk,
		value,
	}
}

/*
The caller should know and specify the exact MasterKeyGen() for particular pqringct version.
*/
//	todo: input and output seed
func MasterKeyGen(inputSeed []byte, cryptoScheme abecrypto.CryptoScheme) (seed []byte, serializedMpk []byte, serializedMsvk []byte, serializedMssk []byte, err error) {
	if len(inputSeed) != 0 {
		cryptoSchemeInSeed := binary.BigEndian.Uint32(inputSeed[:4])
		if uint32(cryptoScheme) != cryptoSchemeInSeed {
			err := errors.New("the CryptoScheme does not match that in the inputSeed")
			return nil, nil, nil, nil, err
		}
	}

	var mpk MasterPublicKey
	var msvk MasterSecretViewKey
	var mssk MasterSecretSignKey

	switch cryptoScheme {
	case abecrypto.CryptoSchemePQRINGCT:
		mpk, msvk, mssk, err = cryptoPP.MasterKeyGen(inputSeed)
		if err != nil {
			return nil, nil, nil, nil, err
		}

	case abecrypto.CryptoSchemePQRINGCTV2:
		// todo: reserve for future versions
	}

	//	todo: seed

	retmpkSer := make([]byte, 4+mpk.SerializeSize())
	binary.BigEndian.PutUint32(retmpkSer, uint32(cryptoScheme))
	copy(retmpkSer[4:], mpk.Serialize())

	retmsvkSer := make([]byte, 4+msvk.SerializeSize())
	binary.BigEndian.PutUint32(retmsvkSer, uint32(cryptoScheme))
	copy(retmsvkSer[4:], msvk.Serialize())

	retmsskSer := make([]byte, 4+mssk.SerializeSize())
	binary.BigEndian.PutUint32(retmsskSer, uint32(cryptoScheme))
	copy(retmsskSer[4:], mssk.Serialize())

	return nil, retmpkSer, retmsvkSer, retmsskSer, nil
}

type CoinbaseTx pqringct.CoinbaseTx

func CoinbaseTxGen(abeTxOutDescs []*AbeTxOutDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	cryptoScheme := abecrypto.CryptoSchemePQRINGCT
	if coinbaseTxMsgTemplate.Version >= 1 {
		//	todo: the Tx.version decide what cryptoScheme should be used
		cryptoScheme = abecrypto.CryptoSchemePQRINGCT
	}

	if cryptoScheme == abecrypto.CryptoSchemePQRINGCT {
		//	pqringct
		txOutDescs := make([]*pqringct.TxOutputDesc, len(abeTxOutDescs))
		for i := 0; i < len(abeTxOutDescs); i++ {
			cryptoSchemeInDesc := binary.BigEndian.Uint16(abeTxOutDescs[i].serializedMasterPublicKey[:4])
			if abecrypto.CryptoScheme(cryptoSchemeInDesc) != cryptoScheme {
				return nil, errors.New("the cryptoScheme in TxOutDesc does not match that implied by the MsgTx.version")
			}
			mpk := &pqringct.MasterPublicKey{}
			err := mpk.Deserialize(abeTxOutDescs[i].serializedMasterPublicKey[4:])
			if err != nil {
				return nil, err
			}

			txOutDescs[i] = pqringct.NewTxOutputDesc(mpk, abeTxOutDescs[i].value)
		}

		coinbaseTx, err := cryptoPP.CoinbaseTxGen(coinbaseTxMsgTemplate.TxFee, txOutDescs)
		if err != nil {
			return nil, err
		}

		coinbaseTxMsgTemplate.TxOuts = make([]*wire.TxOutAbe, len(coinbaseTx.OutputTxos))
		for i := 0; i < len(coinbaseTx.OutputTxos); i++ {
			coinbaseTxMsgTemplate.TxOuts[i] = &wire.TxOutAbe{
				coinbaseTxMsgTemplate.Version,
				coinbaseTx.OutputTxos[i].Serialize(),
			}
		}

		coinbaseTxMsgTemplate.TxWitness = coinbaseTx.TxWitness.Serialize()

		return coinbaseTxMsgTemplate, nil
	}

	return nil, nil
}

func TransferTxGen(mpk []byte, mssk []byte) {
}
