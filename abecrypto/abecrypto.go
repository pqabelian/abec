package abecrypto

import (
	"errors"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

//	data structures for abec side	begin
// 	AbeTxOutputDesc defines the description for Txo generation
type AbeTxOutputDesc struct {
	cryptoAddress []byte // generated by CryptoAddressKeyGen
	value         uint64
}

func (o *AbeTxOutputDesc) GetValue() uint64 {
	return o.value
}

// AbeTxInputDesc defines the data that are need to spend a TxoCoin, in TransferTxGen
type AbeTxInputDesc struct {
	ringHash      chainhash.Hash // txoRing identifier
	txoList       []*wire.TxOutAbe
	sidx          uint8  // spend which one
	cryptoAddress []byte // address, generated by CryptoAddressKeyGen
	cryptoSpsk    []byte // spend secret key, generated by CryptoAddressKeyGen
	cryptoSnsk    []byte //  serial-number secret key, generated by CryptoAddressKeyGen
	cryptoVsk     []byte //  view secret key, generated by CryptoAddressKeyGen
	value         uint64
}

// AbeTxInDetail defines the data describing a consumed TxoCoin in TransferTx, which will be used in TransferTxVerify
type AbeTxInDetail struct {
	ringHash     chainhash.Hash // txoRing identifier
	txoList      []*wire.TxOutAbe
	serialNumber []byte
}

func NewAbeTxInputDesc(ringHash chainhash.Hash, txoList []*wire.TxOutAbe,
	sidx uint8, cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte, value uint64) *AbeTxInputDesc {
	return &AbeTxInputDesc{
		ringHash:      ringHash,
		txoList:       txoList,
		sidx:          sidx,
		cryptoAddress: cryptoAddress,
		cryptoSpsk:    cryptoSpsk,
		cryptoSnsk:    cryptoSnsk,
		cryptoVsk:     cryptoVsk,
		value:         value,
	}
}

func NewAbeTxInDetail(ringHash chainhash.Hash, txoList []*wire.TxOutAbe, serialNumber []byte) *AbeTxInDetail {
	return &AbeTxInDetail{
		ringHash:     ringHash,
		txoList:      txoList,
		serialNumber: serialNumber,
	}
}

func NewAbeTxOutDesc(cryptoAddress []byte, value uint64) *AbeTxOutputDesc {
	return &AbeTxOutputDesc{
		cryptoAddress: cryptoAddress,
		value:         value,
	}
}
func ExtractCoinAddressFromTxoScript(txoscript []byte, cryptoScheme abecryptoparam.CryptoScheme) ([]byte, error) {
	var coinAddr []byte
	var err error
	switch cryptoScheme {
	case abecryptoparam.CryptoSchemePQRingCT:
		coinAddr, err = pqringctExtractCoinAddressFromTxoScript(abecryptoparam.PQRingCTPP, txoscript)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported ringct version")
	}
	return coinAddr, nil
}

//	data structures for abec side	end

//	abecrypto, abecryptoparam
//	Address(Key) Generation, Transaction Generation and Verify, pqringctTxoCoinReceive, pqringctTxoCoinSerialNumberGen are handled in abecrypto,
//	as these functions are (bidirectional) bridges between underlying crypto-scheme and abec, namely, will translate teh data structure between crypto-scheme and abec(.wire).
//	GetTxoSerialSizeApprox, GetNullSerialNumber, etc. are handled in abecryptoparam,
//	as these functions are unidirectional, namely, called only by abec(.wire), and call the corresponding APIs in crypto-scheme.
//	The Public Parameters (pointers) for the underlying crypto-schemes are defined in abecryptoparam,
//	since both the functions in abecryptoparam and those in abecrypto needs to use these Public Parameters to call the APIs in the underlying crypto-schemes.
//	abecrypto.go is the entrance that abec uses the crypto-scheme, and will distribute abec's requirements to the corresponding crypto-scheme,
//	by using the corresponding public parameters and sub-package for the corresponding crypto-scheme, e.g., abecrypto.abepqringct.
//	The sub-package for crypto-scheme (e.g., abecrypto.abepqringct) will process the details, say,
//	translate abec's data structures to crypto-scheme's data structures, call crypto-scheme's APIs, translate the result (in crypto-scheme's data structures) to abec's.

// CryptoAddressKeyGen generate AbeCryptoAddress for specified seed and CryptoScheme.
// The caller (normally wallet) needs to specify the CryptoScheme.
// Requirement-by-Design: The underlying crypto-scheme's must put the crypto-scheme (4 bytes = 32 bits) at the head of the
// returned cryptoAddress, cryptoSpsk, cryptoSnsk, and cryptoVsk.
// By such a design, regardless of the real keys of the underlying crypto-scheme, they have to be encapsed to cryptoAddress, cryptoSpsk, cryptoSnsk, and cryptoVsk.
// By such a design, abecrypto directly calls the functions (except CryptoAddressKeyGen) of underlying crypto-scheme by using the cryptoAddress and cryptoKeys generated by CryptoAddressKeyGen,
// and the crypto-scheme will detach the crypto-scheme in the cryptoAddress and cryptoKeys, and make a check.
//	At this moment, we are using PQRingCT, which requires the seed to be 128 bytes.
func CryptoAddressKeyGen(seed []byte, cryptoScheme abecryptoparam.CryptoScheme) (retCryptoAddress []byte, retCryptoSpsk []byte, retCryptoSnsk []byte, retCryptoVsk []byte, err error) {
	switch cryptoScheme {
	case abecryptoparam.CryptoSchemePQRingCT:
		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, err := pqringctCryptoAddressGen(abecryptoparam.PQRingCTPP, seed, cryptoScheme)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil

	default:
		return nil, nil, nil, nil, errors.New("CryptoAddressKeyGen: unsupported crypto-scheme")
	}
	//return nil, nil, nil, nil, nil
}

func GetCryptoAddressSerializeSize(cryptoScheme abecryptoparam.CryptoScheme) uint32 {
	switch cryptoScheme {
	case abecryptoparam.CryptoSchemePQRingCT:
		return pqringctCryptoAddressSize(abecryptoparam.PQRingCTPP)

	default:
		return 0
	}
}

func CoinbaseTxGen(abeTxOutputDescs []*AbeTxOutputDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	cryptoScheme, err := abecryptoparam.GetCryptoSchemeByTxVersion(coinbaseTxMsgTemplate.Version)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case abecryptoparam.CryptoSchemePQRingCT:
		cbTx, err := pqringctCoinbaseTxGen(abecryptoparam.PQRingCTPP, cryptoScheme, abeTxOutputDescs, coinbaseTxMsgTemplate)
		if err != nil {
			return nil, err
		}
		return cbTx, nil
	default:
		return nil, errors.New("CoinbaseTxGen: Unsupported crypto scheme")
	}

}

func CoinbaseTxVerify(coinbaseTx *wire.MsgTxAbe) (bool, error) {
	cryptoScheme, err := abecryptoparam.GetCryptoSchemeByTxVersion(coinbaseTx.Version)
	if err != nil {
		return false, err
	}

	switch cryptoScheme {
	case abecryptoparam.CryptoSchemePQRingCT:
		valid, err := pqringctCoinbaseTxVerify(abecryptoparam.PQRingCTPP, coinbaseTx)
		if err != nil {
			return false, err
		}
		return valid, nil
	default:
		return false, errors.New("CoinbaseTxVerify: Unsupported crypto scheme")
	}
}

func TransferTxGen(abeTxInputDescs []*AbeTxInputDesc, abeTxOutputDescs []*AbeTxOutputDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	cryptoScheme, err := abecryptoparam.GetCryptoSchemeByTxVersion(transferTxMsgTemplate.Version)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case abecryptoparam.CryptoSchemePQRingCT:
		trTx, err := pqringctTransferTxGen(abecryptoparam.PQRingCTPP, cryptoScheme, abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)
		if err != nil {
			return nil, err
		}
		return trTx, nil
	default:
		return nil, errors.New("TransferTxGen: Unsupported crypto scheme")
	}

}

func TransferTxVerify(transferTx *wire.MsgTxAbe, abeTxInDetails []*AbeTxInDetail) (bool, error) {
	cryptoScheme, err := abecryptoparam.GetCryptoSchemeByTxVersion(transferTx.Version)
	if err != nil {
		return false, err
	}

	switch cryptoScheme {
	case abecryptoparam.CryptoSchemePQRingCT:
		valid, err := pqringctTransferTxVerify(abecryptoparam.PQRingCTPP, transferTx, abeTxInDetails)
		if err != nil {
			return false, err
		}
		return valid, nil
	default:
		return false, errors.New("TransferTxVerify: Unsupported crypto scheme")
	}
}

// TxoCoinReceive checks whether a Txo/Coin belongs to the input cryptoAddress, and return the value if true.
// cryptoAddress/serializedSkvalue is the cryptoAddress/serializedSkvalue generated by the CryptoAddressKeyGen() algorithm,
// and what the format is depends on the underlying crypto-scheme.
// For example, for the current CryptoSchemePQRingCT (which does not suppose stealth cryptoAddress), abecryptoAddress is an Instance Address,
// while for a future version supporting stealth cryptoAddress, cryptoAddress could be a master public key (master cryptoAddress).
func TxoCoinReceive(abeTxo *wire.TxOutAbe, cryptoAddress []byte, cryptoVsk []byte) (bool, uint64, error) {
	cryptoScheme, err := abecryptoparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return false, 0, err
	}

	switch cryptoScheme {
	case abecryptoparam.CryptoSchemePQRingCT:
		valid, value, err := pqringctTxoCoinReceive(abecryptoparam.PQRingCTPP, cryptoScheme, abeTxo, cryptoAddress, cryptoVsk)
		if err != nil {
			return false, 0, err
		}
		return valid, value, nil

	default:
		return false, 0, errors.New("TxoCoinReceive: unsupported crypto scheme")
	}
}

// Abec uses the fixed-ring mechanism, and uses (ringHash, index) as the uniqe identifier of Txo in blockchain.
// serializedSksn is the serializedSksn generated by the CryptoAddressKeyGen() algorithm,
// and what the format is depends on the underlying crypto-scheme.
func TxoCoinSerialNumberGen(txo *wire.TxOutAbe, ringHash chainhash.Hash, txoIndexInRing uint8, serializedSksn []byte) ([]byte, error) {
	cryptoScheme, err := abecryptoparam.GetCryptoSchemeByTxVersion(txo.Version)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case abecryptoparam.CryptoSchemePQRingCT:
		sn, err := pqringctTxoCoinSerialNumberGen(abecryptoparam.PQRingCTPP, abecryptoparam.CryptoSchemePQRingCT, txo, ringHash, txoIndexInRing, serializedSksn)
		if err != nil {
			return nil, err
		}
		return sn, nil

	default:
		return nil, errors.New("TxoCoinSerialNumberGen: Unsupported crypto scheme")
	}
}

//
//func TxoSerialNumberGen(txo *wire.TxOutAbe, ringHash chainhash.Hash, serializedSksn []byte) []byte {
//	var sn []byte
//
//	cryptoScheme := abecryptoparam.GetCryptoSchemeByTxVersion(txo.Version)
//
//	switch cryptoScheme {
//	case abecryptoparam.CryptoSchemePQRingCT:
//		// parse cryptoAddress -> cryptoAddress public key and value public key
//		sn = TxoSerialNumberGen(abecryptoparam.PQRingCTPP, txo, ringHash, serializedSksn)
//	default:
//		log.Fatalln("Unsupported crypto scheme ")
//	}
//	return sn
//}
