package abecrypto

import (
	"bytes"
	"errors"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/cryptosuite/pqringct"
	"log"
)

//	ABE can support at most 2^32 different CryptoSchemes
//	The different versions of 'same' CryptoSchemes are regarded as different CryptoSchemes.
//	e.g. SalrsV0, SalrsV1

type CryptoScheme uint32

const (
	CryptoSchemeSALRS      CryptoScheme = 0
	CryptoSchemePQRINGCT   CryptoScheme = 1
	CryptoSchemePQRINGCTV2 CryptoScheme = 2
)

func GetCryptoScheme(version uint32) CryptoScheme {
	//	todo: for each version, there is a corresponding CryptoScheme
	return CryptoSchemePQRINGCT
}

type AbeCryptoParam struct {
	Version CryptoScheme
	RingCT  *pqringct.PublicParameter
}

var CryptoPP = &AbeCryptoParam{
	Version: CryptoSchemePQRINGCTV2,
	RingCT:  pqringct.DefaultPPV2,
}

// LedgerTxoIDCompute(ringID, idx) → txolid.
func LedgerTXOSerialNumberGen(txo []byte, txolid []byte, sksn []byte) []byte {
	panic("implement me")
	return nil
}

// 											View of Abec :  			Address , Proof
// 																			\	 /
// 											View of Abewallet[TrTxGen] : 	(Pk,Sk)
// ------------  [KeyGen,CbTxGen/Vrf,TrTxGen/Vrf]  	 \
// pqringct   | --->  abepqringct  -------------> 	abecrypto -> abec[CoinbaseTxGen,CoinbaseTxVrf,TrTxVrg]
// 			  |					    			/	[AddressKeyGen,]
// pqringctv2 | --->  abepqringctv2 -----------

// abec call coinbaseTxGen() -> abecrypto.coinbaseTxGen()->pqringct.coinbaseTxGen()?pqringctv2.coinbaseTxGen()?
// parse the address to different struct

// 20220320 Input and Output struct should be defined by config and decide to assign to which version
type AbeTxInputDesc struct {
	ringHash     chainhash.Hash // txoRing identifier
	txoList      []*wire.TxOutAbe
	sidx         int // spend which one
	serializedSk []byte
}

func NewAbeTxInputDesc(ringHash chainhash.Hash, txoList []*wire.TxOutAbe,
	sidx int, serializedSk []byte) *AbeTxInputDesc {
	return &AbeTxInputDesc{
		ringHash:     ringHash,
		txoList:      txoList,
		sidx:         sidx,
		serializedSk: serializedSk,
	}
}

// 20220320 for trTx verify
type AbeTxInDetail struct {
	ringHash     chainhash.Hash // txoRing identifier
	txoList      []*wire.TxOutAbe
	serialNumber []byte
}

func NewAbeTxInDetail(ringHash chainhash.Hash, txoList []*wire.TxOutAbe, serialNumber []byte) *AbeTxInDetail {
	return &AbeTxInDetail{
		ringHash:     ringHash,
		txoList:      txoList,
		serialNumber: serialNumber,
	}
}

// 20220320 for trTxGen and cbTxGen
type AbeTxOutDesc struct {
	address []byte
	value   uint64
}

func (txout *AbeTxOutDesc) GetValue() uint64 {
	return txout.value
}
func NewAbeTxOutDesc(address []byte, value uint64) *AbeTxOutDesc {
	return &AbeTxOutDesc{
		address: address,
		value:   value,
	}
}

func (pp *AbeCryptoParam) AbeCryptoAddressGen(seed []byte) (retSerializedCryptoAddress []byte, retSerializedVSk []byte, retSerializedASksp []byte, retSerializedASksn []byte, err error) {
	var serializedAddress, serializedVSk, serializedASkSp, serializedASkSn []byte
	switch pp.Version {
	case CryptoSchemePQRINGCTV2:
		serializedAddress, serializedVSk, serializedASkSp, serializedASkSn, err = CryptoAddressGen(pp.RingCT, seed)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	default:
		return nil, nil, nil, nil, errors.New("unsupported ringct version")
	}
	retSerializedCryptoAddress = make([]byte, 0, 4+len(serializedAddress))
	retSerializedCryptoAddress = append(retSerializedCryptoAddress, byte(pp.Version>>0))
	retSerializedCryptoAddress = append(retSerializedCryptoAddress, byte(pp.Version>>8))
	retSerializedCryptoAddress = append(retSerializedCryptoAddress, byte(pp.Version>>16))
	retSerializedCryptoAddress = append(retSerializedCryptoAddress, byte(pp.Version>>24))
	retSerializedCryptoAddress = append(retSerializedCryptoAddress, serializedAddress...)

	retSerializedVSk = make([]byte, 0, 4+len(serializedVSk))
	retSerializedVSk = append(retSerializedVSk, byte(pp.Version>>0))
	retSerializedVSk = append(retSerializedVSk, byte(pp.Version>>8))
	retSerializedVSk = append(retSerializedVSk, byte(pp.Version>>16))
	retSerializedVSk = append(retSerializedVSk, byte(pp.Version>>24))
	retSerializedVSk = append(retSerializedVSk, serializedVSk...)

	retSerializedASksp = make([]byte, 0, 4+len(serializedASkSp))
	retSerializedASksp = append(retSerializedASksp, byte(pp.Version>>0))
	retSerializedASksp = append(retSerializedASksp, byte(pp.Version>>8))
	retSerializedASksp = append(retSerializedASksp, byte(pp.Version>>16))
	retSerializedASksp = append(retSerializedASksp, byte(pp.Version>>24))
	retSerializedASksp = append(retSerializedASksp, serializedASkSp...)

	retSerializedASksn = make([]byte, 0, 4+len(serializedASkSn))
	retSerializedASksn = append(retSerializedASksn, byte(pp.Version>>0))
	retSerializedASksn = append(retSerializedASksn, byte(pp.Version>>8))
	retSerializedASksn = append(retSerializedASksn, byte(pp.Version>>16))
	retSerializedASksn = append(retSerializedASksn, byte(pp.Version>>24))
	retSerializedASksn = append(retSerializedASksn, serializedASkSn...)

	return retSerializedCryptoAddress, retSerializedVSk, retSerializedASksp, retSerializedASksn, nil
}

func (pp *AbeCryptoParam) CoinbaseTxGen(abeTxOutDescs []*AbeTxOutDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	var cbTx *wire.MsgTxAbe
	var err error
	switch pp.Version {
	case CryptoSchemePQRINGCTV2:
		// check the address in abeTxOutDescs
		for i := 0; i < len(abeTxOutDescs); i++ {
			version := abeTxOutDescs[i].address[0]
			version |= abeTxOutDescs[i].address[1]
			version |= abeTxOutDescs[i].address[2]
			version |= abeTxOutDescs[i].address[3]
			if CryptoScheme(version) != CryptoSchemePQRINGCTV2 {
				return nil, errors.New("unmatched version and address")
			}
			abeTxOutDescs[i].address = abeTxOutDescs[i].address[4:]
		}
		cbTx, err = CoinbaseTxGen(pp.RingCT, abeTxOutDescs, coinbaseTxMsgTemplate)
		if err != nil {
			return nil, err
		}
	default:
		log.Fatalln("Unsupporte crypto scheme")
	}
	return cbTx, nil
}
func (pp *AbeCryptoParam) CoinbaseTxVerify(coinbaseTx *wire.MsgTxAbe) bool {
	var b bool
	switch pp.Version {
	case CryptoSchemePQRINGCTV2:
		// parse address -> address public key and value public key
		b = CoinbaseTxVerify(pp.RingCT, coinbaseTx)
	default:
		log.Fatalln("Unsupporte crypto scheme")
	}
	return b
}

func (pp *AbeCryptoParam) TransferTxGen(
	abeTxInputDescs []*AbeTxInputDesc, abeTxOutputDescs []*AbeTxOutDesc,
	transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	var cbTx *wire.MsgTxAbe
	var err error
	switch pp.Version {
	case CryptoSchemePQRINGCTV2:
		// parse address -> address public key and value public key
		cbTx, err = TransferTxGen(pp.RingCT, abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)
		if err != nil {
			return nil, err
		}
	default:
		log.Fatalln("Unsupporte crypto scheme")
	}
	return cbTx, nil
}
func (pp *AbeCryptoParam) TransferTxVerify(transferTx *wire.MsgTxAbe, abeTxInDetails []*AbeTxInDetail) bool {
	var b bool
	switch pp.Version {
	case CryptoSchemePQRINGCTV2:
		// parse address -> address public key and value public key
		b = TransferTxVerify(pp.RingCT, transferTx, abeTxInDetails)
	default:
		log.Fatalln("Unsupporte crypto scheme")
	}
	return b
}

func (pp *AbeCryptoParam) TxoSerialNumberGen(txo *wire.TxOutAbe, ringHash chainhash.Hash, serializedSksn []byte) []byte {
	var sn []byte
	switch pp.Version {
	case CryptoSchemePQRINGCTV2:
		// parse address -> address public key and value public key
		sn = TxoSerialNumberGen(pp.RingCT, txo, ringHash, serializedSksn)
	default:
		log.Fatalln("Unsupporte crypto scheme")
	}
	return sn
}

func (pp *AbeCryptoParam) TxoCoinReceive(abeTxo *wire.TxOutAbe, address []byte, serializedSkvalue []byte) (bool, uint64) {
	var valid bool
	var b uint64
	switch pp.Version {
	case CryptoSchemePQRINGCTV2:
		// parse address -> address public key and value public key
		version := address[0]
		version |= address[1]
		version |= address[2]
		version |= address[3]
		if CryptoScheme(version) != CryptoSchemePQRINGCTV2 {
			return false, 0
		}
		version = serializedSkvalue[0]
		version |= serializedSkvalue[1]
		version |= serializedSkvalue[2]
		version |= serializedSkvalue[3]
		if CryptoScheme(version) != CryptoSchemePQRINGCTV2 {
			return false, 0
		}
		serializedSkvalue = serializedSkvalue[4:]
		valid, b = TxoCoinReceive(pp.RingCT, abeTxo, address, serializedSkvalue)
	default:
		log.Fatalln("Unsupporte crypto scheme")
	}
	return valid, b
}
func LedgerTxoIdGen(ringHash chainhash.Hash, index int) []byte {
	w := bytes.NewBuffer(make([]byte, 0, 36))
	var err error
	// ringHash
	_, err = w.Write(ringHash[:])
	if err != nil {
		return nil
	}
	// index
	err = w.WriteByte(byte(index >> 0))
	if err != nil {
		return nil
	}
	err = w.WriteByte(byte(index >> 1))
	if err != nil {
		return nil
	}
	err = w.WriteByte(byte(index >> 2))
	if err != nil {
		return nil
	}
	err = w.WriteByte(byte(index >> 3))
	if err != nil {
		return nil
	}
	return chainhash.DoubleHashB(w.Bytes())
}

func (pp *AbeCryptoParam) GetTxoSerializeSize(version uint32) int {
	var length int
	switch pp.Version {
	case CryptoSchemePQRINGCTV2:
		// parse address -> address public key and value public key
		length = GetTxoSerializeSize(pp.RingCT, version)
	default:
		log.Fatalln("Unsupporte crypto scheme")
	}
	return length
}
func (pp *AbeCryptoParam) GetCoinbaseTxWitnessLen(version uint32, num int) int {
	return GetCoinbaseTxWitnessLen(pp.RingCT, version)
}
func (pp *AbeCryptoParam) GetTxoSerialNumberLen(version uint32) int {
	return GetTxoSerializeSize(pp.RingCT, version)
}
func (pp *AbeCryptoParam) GetNullSerialNumber(version uint32) []byte {
	return GetNullSerialNumber(pp.RingCT, version)
}

func (pp *AbeCryptoParam) GetTxMemoMaxLen(version uint32) int {
	return GetTxMemoMaxLen(pp.RingCT, version)
}
func (pp *AbeCryptoParam) GetTxWitnessMaxLen(version uint32) int {
	return GetTxWitnessMaxLen(pp.RingCT, version)
}
func (pp *AbeCryptoParam) GetTrTxWitnessSize(txVersion uint32, inputRingVersion uint32, inputRingSizes []int, outputTxoNum uint8) int {
	return GetTrTxWitnessSize(pp.RingCT, inputRingSizes, int(outputTxoNum))
}
