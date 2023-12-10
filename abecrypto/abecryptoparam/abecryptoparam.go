package abecryptoparam

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cryptosuite/pqringct"
)

// For 0x12345678
// Big-Endian
// ____________________________
// _0x12_|_0x34_|_0x56_|_0x78_|
//	a     a+1     a+2    a+3

// Little-Endian
// ____________________________
// _0x78_|_0x56_|_0x34_|_0x12_|
//	a     a+1     a+2    a+3

// ABE can support at most 2^32 different CryptoSchemes
// The different versions of 'same' CryptoSchemes are regarded as different CryptoSchemes.
type CryptoScheme uint32

// Serialize use little endian to serialize a uint32 number
func (c CryptoScheme) Serialize() []byte {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, uint32(c))
	return res
}

func DeserializeCryptoScheme(content []byte) (CryptoScheme, error) {
	if len(content) != 4 {
		return CryptoSchemePQRingCT, errors.New("invalid length")
	}
	return CryptoScheme(binary.LittleEndian.Uint32(content)), nil
}

const (
	CryptoSchemePQRingCT CryptoScheme = 0
	//CryptoSchemePQRingCTV2
)

// The public parameters for the supported crypto-schemes.
// PQRingCTPP is the public parameter for CryptoSchemePQRingCT.
var PQRingCTPP = pqringct.Initialize([]byte("Welcome to Post Quantum World! From the Abelian Team"))

// var PQRingCT2PP = pqringct2.DefaultPP

// These constants are related/decided by the underlying crypto-schemes.
// When underlying crypto-schemes are updated, we need to check these constants, and update them when necessary.
const (
	//	PQRingCT, 2022.03.31
	MaxAllowedTxoSize = 1048576 //1024*1024*1, 1M bytes
)
const ( // copyed from pqringct 2022.04.15
	MAXALLOWED                  uint32 = 4294967295 // 2^32-1
	MaxAllowedKemCiphertextSize uint32 = 1048576    // 2^20, 1M bytes
	MaxAllowedTxMemoSize        uint32 = 1024       // 1024 bytes
	MaxAllowedSerialNumberSize  uint32 = 64         // 512 bits = 64 bytes
	MaxAllowedChallengeSeedSize uint32 = 64         // use SHA512 to generate the challenge seed
	MaxAllowedRpulpProofSize    uint32 = 8388608    // 2^23, 8M bytes
	MaxAllowedTxWitnessSize     uint32 = 16777216   // 2^24, 16M bytes
	MaxAllowedElrsSignatureSize uint32 = 8388608    // 2^23, 8M bytes
	MaxAllowedTrTxInputSize     uint32 = 8388608    // 2^23, 8M bytes
)

//	The mapping between TxVersion/TxoVersion/RingVersion/ and crypto-scheme	begin
//
// GetCryptoSchemeByTxVersion returns the CrypoScheme corresponding to the input TxVersion/TxoVersion/RingVersion.
// For each TxVersion, there is a corresponding CryptoScheme, while multiple TxVersions may use the same CryptoScheme.
// The package abec.abecrypto will access the function.
func GetCryptoSchemeByTxVersion(txVersion uint32) (CryptoScheme, error) {
	//	todo: for each version, there is a corresponding CryptoScheme
	switch txVersion {
	case 1:
		return CryptoSchemePQRingCT, nil
	default:
		return 0, errors.New("GetCryptoSchemeByTxVersion: Unsupported TxVersion")
	}
}

// GetCurrentCryptoScheme return the crypto-scheme that is currently used by the blockchian.
// In other words, the crypto-scheme corresponding to the current TxVersion is returned.
func GetCurrentCryptoScheme() CryptoScheme {
	//	When the current TxVersion is updated due to crypto-scheme update, here the updated crypto-scheme is set.
	return CryptoSchemePQRingCT
}

//	The mapping between TxVersion/TxoVersion/RingVersion/ and crypto-scheme	end

// GetTxInputMaxNum returns the allowed maximum number of inputs for transaction, which is decided by the TxVersion.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the allowed maximum number of inputs actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
func GetTxInputMaxNum(txVersion uint32) (int, error) {
	switch txVersion {
	// todo: for each version, there is a corresponding CryptoScheme.
	// Here we call the function of corresponding crypto-scheme
	case 1:
		return pqringct.GetTxInputMaxNum(PQRingCTPP), nil

	default:
		return 0, errors.New("GetTxInputMaxNum: Unsupported TxVersion")
	}
}

// GetTxOutputMaxNum returns the allowed maximum number of outputs for transaction, which is decided by the TxVersion.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the allowed maximum number of outputs actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
func GetTxOutputMaxNum(txVersion uint32) (int, error) {
	switch txVersion {
	case 1:
		return pqringct.GetTxOutputMaxNum(PQRingCTPP), nil

	default:
		return 0, errors.New("GetTxOutputMaxNum: Unsupported TxVersion")
	}
}

// GetSerialNumberSerializeSize returns the exact serialize size for SerialNumber, which is decided by the TxVersion.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for SerialNumber actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
func GetSerialNumberSerializeSize(txVersion uint32) (int, error) {
	switch txVersion {
	case 1:
		//	CryptoSchemePQRingCT
		return pqringct.GetSerialNumberSerializeSize(PQRingCTPP), nil
	default:
		return 0, errors.New("GetCbTxWitnessSerializeSizeApprox: Unsupported txVersion")
	}
}

// GetNullSerialNumber() return the null serial number.
func GetNullSerialNumber(txVersion uint32) ([]byte, error) {
	switch txVersion {
	case 1:
		//	CryptoSchemePQRingCT
		return pqringct.GetNullSerialNumber(PQRingCTPP), nil
	default:
		return nil, errors.New("GetNullSerialNumber: Unsupported txVersion")
	}
}

// GetTxoSerializeSizeApprox returns the approximate serialize size for Txo, which is decided by the TxVersion.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for Txo actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
func GetTxoSerializeSizeApprox(txVersion uint32) (int, error) {
	switch txVersion {
	case 1:
		return pqringct.GetTxoSerializeSizeApprox(PQRingCTPP), nil
	default:
		return 0, errors.New("GetTxoSerializeSizeApprox: Unsupported txVersion")
	}
}

// GetCbTxWitnessSerializeSizeApprox returns the approximate serialize size for CoinbaseTxWitness, which is decided by the TxVersion and the number of out Txo.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for CoinbaseTxWitness actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
func GetCbTxWitnessSerializeSizeApprox(txVersion uint32, outTxoNum int) (int, error) {
	switch txVersion {
	case 1:
		return pqringct.GetCbTxWitnessSerializeSizeApprox(PQRingCTPP, outTxoNum), nil
	default:
		return 0, errors.New("GetCbTxWitnessSerializeSizeApprox: Unsupported txVersion")
	}
}

// GetTrTxWitnessSerializeSizeApprox() returns the approximate serialize size for TrTxWitness, which is decided by the TxVersion, inputRingSizes, and the number of out Txo.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for TrTxWitness actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
// In the future, the inputRingVersion may be different from the txVersion.
// At this moment, inputRingVersion is the same as txVersion.
func GetTrTxWitnessSerializeSizeApprox(txVersion uint32, inputRingVersion uint32, inputRingSizes []int, outputTxoNum int) (int, error) {
	switch txVersion {
	case 1:
		return pqringct.GetTrTxWitnessSerializeSizeApprox(PQRingCTPP, inputRingSizes, outputTxoNum), nil
	default:
		return 0, errors.New("GetTrTxWitnessSerializeSizeApprox: Unsupported txVersion")
	}
}

// CryptoAddressParse will be used to parse the cryptoAddress generated by CryptoAddressKeyGen, to coinAddress and valuePublicKey.
// reviewed on 2023.12.07
func CryptoAddressParse(cryptoAddress []byte) (serializedAPK []byte, serializedVPK []byte, err error) {
	cryptoScheme, err := ExtractCryptoSchemeFromCryptoAddress(cryptoAddress)
	if err != nil {
		return nil, nil, err
	}

	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		return pqringctCryptoAddressParse(PQRingCTPP, cryptoScheme, cryptoAddress)

	default:
		return nil, nil, errors.New("ParseCryptoAddress: non-supported cryptoScheme appears in cryptoAddress")
	}
}

func CryptoSpendSecretKeyParse(cryptoSpendSecretKey []byte) (serializedSpendSecretKey []byte, err error) {
	cryptoScheme, err := ExtractCryptoSchemeFromCryptoSpsk(cryptoSpendSecretKey)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		return pqringctCryptoSpendSecretKeyParse(PQRingCTPP, cryptoScheme, cryptoSpendSecretKey)

	default:
		return nil, errors.New("CryptoSpendSecretKeyParse: non-supported cryptoScheme appears in serializedSpendSecretKey")
	}
}

func CryptoSerialNumberSecretKeyParse(cryptoSerialNumberSecretKey []byte) (serializedSerialNumberSecretKey []byte, err error) {
	cryptoScheme, err := ExtractCryptoSchemeFromCryptoSnsk(cryptoSerialNumberSecretKey)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		return pqringctCryptoSerialNumberSecretKeyParse(PQRingCTPP, cryptoScheme, serializedSerialNumberSecretKey)

	default:
		return nil, errors.New("CryptoSerialNumberSecretKeyParse: non-supported cryptoScheme appears in serializedSerialNumberSecretKey")
	}
}

func CryptoValueSecretKeyParse(cryptoValueSecretKey []byte) (coinValueSecretKey []byte, err error) {
	cryptoScheme, err := ExtractCryptoSchemeFromCryptoVsk(cryptoValueSecretKey)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		return pqringctCryptoValueSecretKeyParse(PQRingCTPP, cryptoScheme, coinValueSecretKey)

	default:
		return nil, errors.New("CryptoSerialNumberSecretKeyParse: non-supported cryptoScheme appears in serializedSerialNumberSecretKey")
	}
}

// refactored when adding abecryptox	begin

// ExtractCryptoSchemeFromCryptoAddress extracts cryptoScheme from cryptoAddress
// reviewed on 2023.12.07
func ExtractCryptoSchemeFromCryptoAddress(cryptoAddress []byte) (cryptoScheme CryptoScheme, err error) {
	if len(cryptoAddress) < 4 {
		return 0, fmt.Errorf("ExtractCryptoSchemeFromCryptoAddress: incorrect length of cryptoAddress: %d", len(cryptoAddress))
	}

	return DeserializeCryptoScheme(cryptoAddress[:4])

}

// ExtractCryptoSchemeFromCryptoSpsk extracts cryptoScheme from CryptoSpsk
func ExtractCryptoSchemeFromCryptoSpsk(cryptoSpsk []byte) (cryptoScheme CryptoScheme, err error) {
	if len(cryptoSpsk) < 4 {
		errStr := fmt.Sprintf("ExtractCryptoSchemeFromCryptoSpsk: incorrect length of cryptoSpsk: %d", len(cryptoSpsk))
		return 0, errors.New(errStr)
	}

	return DeserializeCryptoScheme(cryptoSpsk[:4])

}

// ExtractCryptoSchemeFromCryptoSnsk extracts cryptoScheme from cryptoSnsk
func ExtractCryptoSchemeFromCryptoSnsk(cryptoSnsk []byte) (cryptoScheme CryptoScheme, err error) {
	if len(cryptoSnsk) < 4 {
		errStr := fmt.Sprintf("ExtractCryptoSchemeFromCryptoSnsk: incorrect length of cryptoSnsk: %d", len(cryptoSnsk))
		return 0, errors.New(errStr)
	}

	return DeserializeCryptoScheme(cryptoSnsk[:4])

}

// ExtractCryptoSchemeFromCryptoVsk extracts cryptoScheme from cryptoAddress
func ExtractCryptoSchemeFromCryptoVsk(cryptoVsk []byte) (cryptoScheme CryptoScheme, err error) {
	if len(cryptoVsk) < 4 {
		errStr := fmt.Sprintf("ExtractCryptoSchemeFromCryptoVsk: incorrect length of cryptoVsk: %d", len(cryptoVsk))
		return 0, fmt.Errorf(errStr)
	}

	return DeserializeCryptoScheme(cryptoVsk[:4])

}

// GetCryptoSchemeParamSeedBytesLen returns the required CryptoSchemeParamSeedBytesLen by the underlying crypto-scheme.
// reviewed on 2023.12.07
func GetCryptoSchemeParamSeedBytesLen(cryptoScheme CryptoScheme) (int, error) {
	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		return pqringctGetParamSeedBytesLen(PQRingCTPP), nil

	default:
		return 0, fmt.Errorf("GetParamSeedBytesLen: unsupported crypto-scheme")
	}
}

// refactored when adding abecryptox	end
