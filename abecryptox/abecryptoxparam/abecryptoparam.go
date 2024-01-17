package abecryptoxparam

import (
	"encoding/binary"
	"fmt"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/cryptosuite/pqringctx/pqringctxapi"
)

// This package will be called/imported by wire and blokchain paackage, at the same position of abecryptox package.
// But abecryptox package (the codes in abecrypto.go and ab) will also call this package.
// This package will directly call functions in abepqringctxparam.go and other abeXXXparam.go.
// The architecture is
// blockchain ---> abecryptox/abecrypto.go  ---> abepqringctx.go ---> wire ---> abecryptoxparam ---> pqringctxapi
//                                               abepqringctx.go -------------> abecryptoxparam ---> pqringctxapi
//                                               abepqringctx.go ----------------------------------> pqringctxapi
// blockchain ----------------------------------------------------------------> abecryptoxparam ---> pqringctxapi
// For back-compatability
// abeccryptox.go --------> abecrypto.go
// abeccryptoxparam.go -------------------------------------------------------->abecryptoparam

// ABE can support at most 2^32 different CryptoSchemes
// The different versions of 'same' CryptoSchemes are regarded as different CryptoSchemes.
type CryptoScheme uint32

// reviewed on 2023.12.07
const (
	CryptoSchemePQRingCT  CryptoScheme = 0
	CryptoSchemePQRingCTX CryptoScheme = 1 // supporting full-privacy and pseudonym-privacy
)

// The public parameters for the supported crypto-schemes.
// PQRingCTPP is the public parameter for CryptoSchemePQRingCT.
// reviewed on 2023.12.07
// var PQRingCTPP = pqringct.Initialize([]byte("Welcome to Post Quantum World! From the Abelian Team"))
var PQRingCTXPP = pqringctxapi.InitializePQRingCTX([]byte("Welcome to Post Quantum World! From the Abelian Team"))

func CryptoSchemeSerializeSize(cryptoScheme CryptoScheme) int {
	return 4
}

// SerializeCryptoScheme serialize the input CryptoScheme, using little endian to serialize an uint32 number.
// reviewed on 2023.12.07
func SerializeCryptoScheme(cryptoScheme CryptoScheme) []byte {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, uint32(cryptoScheme))
	return res
}

// DeserializeCryptoScheme deserialize the input []byte to a CryptoScheme, using little endian.
// reviewed on 2023.12.07
// reviewed on 2023.12.12
func DeserializeCryptoScheme(serializedCryptoScheme []byte) (CryptoScheme, error) {
	if len(serializedCryptoScheme) != 4 {
		return CryptoSchemePQRingCTX, fmt.Errorf("DeserializeCryptoScheme: invalid length")
	}
	return CryptoScheme(binary.LittleEndian.Uint32(serializedCryptoScheme)), nil
}

//	The mapping between TxVersion/TxoVersion/RingVersion/ and crypto-scheme	begin
//
// GetCryptoSchemeByTxVersion returns the CrypoScheme corresponding to the input TxVersion/TxoVersion/RingVersion.
// For each TxVersion, there is a corresponding CryptoScheme, while multiple TxVersions may use the same CryptoScheme.
// The package abec.abecryptox will access the function.
// reviewed on 2023.12.07
func GetCryptoSchemeByTxVersion(txVersion uint32) (CryptoScheme, error) {
	//	todo: for each version, there is a corresponding CryptoScheme
	switch txVersion {
	case 1: // wire.TxVersion_Height_0
		return CryptoSchemePQRingCT, nil
	case 2: // wire.TxVersion_Height_MLPAUT_280000
		return CryptoSchemePQRingCTX, nil
	default:
		return 0, fmt.Errorf("GetCryptoSchemeByTxVersion: Unsupported TxVersion")
	}
}

// GetCurrentCryptoScheme return the crypto-scheme that is currently used by the blockchain.
// In other words, the crypto-scheme corresponding to the current TxVersion is returned.
// reviewed on 2023.12.07
func GetCurrentCryptoScheme() CryptoScheme {
	//	When the current TxVersion is updated due to crypto-scheme update, here the updated crypto-scheme is set.
	return CryptoSchemePQRingCTX
}

//	The mapping between TxVersion/TxoVersion/RingVersion/ and crypto-scheme	end

//	Transaction-related Params	begin
//
// GetTxInputMaxNum returns the allowed maximum number of inputs for transaction, which is decided by the TxVersion.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the allowed maximum number of inputs actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
// reviewed on 2024.01.03
func GetTxInputMaxNum(txVersion uint32) (int, error) {
	switch txVersion {
	// todo: for each version, there is a corresponding CryptoScheme.
	// Here we call the function of corresponding crypto-scheme
	case 1: // wire.TxVersion_Height_0:
		return abecryptoparam.GetTxInputMaxNum(txVersion)

	case 2: // wire.TxVersion_Height_MLPAUT_280000:
		return pqringctxGetTxInputMaxNum(PQRingCTXPP), nil

	default:
		return 0, fmt.Errorf("GetTxInputMaxNum: the input txVersion (%d) is not supported", txVersion)
	}
}

// GetTxOutputMaxNum returns the allowed maximum number of outputs for transaction, which is decided by the TxVersion.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the allowed maximum number of outputs actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
// reviewed on 2024.01.03
func GetTxOutputMaxNum(txVersion uint32) (int, error) {
	switch txVersion {
	case 1: //wire.TxVersion_Height_0:
		return abecryptoparam.GetTxOutputMaxNum(txVersion)

	case 2: //wire.TxVersion_Height_MLPAUT_280000:
		return pqringctxGetTxOutputMaxNum(PQRingCTXPP), nil

	default:
		return 0, fmt.Errorf("GetTxOutputMaxNum: the input txVersion (%d) is not supported", txVersion)
	}
}

// GetSerialNumberSerializeSize returns the exact serialize size for SerialNumber, which is decided by the TxVersion.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for SerialNumber actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
func GetSerialNumberSerializeSize(txVersion uint32) (int, error) {
	cryptoScheme, err := GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}
	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		return abecryptoparam.GetSerialNumberSerializeSize(txVersion)
	case CryptoSchemePQRingCTX:
		return pqringctxGetSerialNumberSize(PQRingCTXPP), nil
	default:
		return 0, fmt.Errorf("GetNullSerialNumber: Unsupported txVersion")
	}
}

// GetNullSerialNumber return the null-serial-number.
// Note that to be simple and back-compatible, PQRingCTX use the same null-serial-number as PQRingCT.
// reviewed on 2023.12.07
func GetNullSerialNumber(txVersion uint32) ([]byte, error) {
	cryptoScheme, err := GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return nil, err
	}
	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		return abecryptoparam.GetNullSerialNumber(txVersion)
	case CryptoSchemePQRingCTX:
		return pqringctxGetNullSerialNumber(PQRingCTXPP), nil
	default:
		return nil, fmt.Errorf("GetNullSerialNumber: Unsupported txVersion")
	}
}

//	Transaction-related Params	end

// APIs providing params of underlying CryptoScheme		begin

// APIs providing params of underlying CryptoScheme		end

// API for Sizes	begin

// GetCryptoSchemeParamSeedBytesLen returns the ParamSeedBytesLen for the input param cryptoScheme.
// The caller may call this API to obtain the ParamSeedBytesLen for the input param cryptoScheme,
// then prepare randSeed for CryptoAddressKeyGen().
// reviewed on 2023.12.07
func GetCryptoSchemeParamSeedBytesLen(cryptoScheme CryptoScheme) (int, error) {
	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		//	this is to achieve back-compatibility with PQRingCT
		return abecryptoparam.GetCryptoSchemeParamSeedBytesLen(abecryptoparam.CryptoSchemePQRingCT)

	case CryptoSchemePQRingCTX:
		return pqringctxGetCryptoSchemeParamSeedBytesLen(PQRingCTXPP), nil

	default:
		return 0, fmt.Errorf("GetCryptoSchemeParamSeedBytesLen: unsupported crypto-scheme")
	}

	return 0, nil
}

func GetTxoSerializeSize(coinAddress []byte) (int, error) {
	return pqringctxapi.GetTxoSerializeSize(PQRingCTXPP, coinAddress)
}

// API for Sizes	end
