package abecryptoxparam

import (
	"encoding/binary"
	"errors"
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

const (
	CryptoSchemePQRingCT  CryptoScheme = 0
	CryptoSchemePQRingCTX CryptoScheme = 1 // supporting full-privacy and pseudonym-privacy
)

type PrivacyLevel uint8

const (
	PrivacyLevelRINGCTPre PrivacyLevel = 0 //	hide the payer in ring, hide the amount by commitment, the default privacy-level in the initial version
	PrivacyLevelRINGCT    PrivacyLevel = 1 //	hide the payer in ring, hide the amount by commitment, same as the initial version, but explicitly specified
	PrivacyLevelPSEUDONYM PrivacyLevel = 2 //	pseudonym, i.e., hide the real identity
	// PrivacyLevelRINGCTSA  PrivacyLevel = 3 //	(not supported at this moment) hide the payer in ring, hide the amount by commitment, hide the payee by SA
)

// The public parameters for the supported crypto-schemes.
// PQRingCTPP is the public parameter for CryptoSchemePQRingCT.
// var PQRingCTPP = pqringct.Initialize([]byte("Welcome to Post Quantum World! From the Abelian Team"))
var PQRingCTXPP = pqringctxapi.InitializePQRingCTX([]byte("Welcome to Post Quantum World! From the Abelian Team"))

// Serialize use little endian to serialize a uint32 number
func SerializeCryptoScheme(cryptoScheme CryptoScheme) []byte {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, uint32(cryptoScheme))
	return res
}

func DeserializeCryptoScheme(content []byte) (CryptoScheme, error) {
	if len(content) != 4 {
		return CryptoSchemePQRingCTX, errors.New("invalid length")
	}
	return CryptoScheme(binary.LittleEndian.Uint32(content)), nil
}

//	The mapping between TxVersion/TxoVersion/RingVersion/ and crypto-scheme	begin
//
// GetCryptoSchemeByTxVersion returns the CrypoScheme corresponding to the input TxVersion/TxoVersion/RingVersion.
// For each TxVersion, there is a corresponding CryptoScheme, while multiple TxVersions may use the same CryptoScheme.
// The package abec.abecryptox will access the function.
func GetCryptoSchemeByTxVersion(txVersion uint32) (CryptoScheme, error) {
	//	todo: for each version, there is a corresponding CryptoScheme
	switch txVersion {
	case 1: // wire.TxVersion_Height_0
		return CryptoSchemePQRingCT, nil
	case 2: // wire.TxVersion_Height_MLPAUT_236000
		return CryptoSchemePQRingCTX, nil
	default:
		return 0, errors.New("GetCryptoSchemeByTxVersion: Unsupported TxVersion")
	}
}

// GetCurrentCryptoScheme return the crypto-scheme that is currently used by the blockchain.
// In other words, the crypto-scheme corresponding to the current TxVersion is returned.
func GetCurrentCryptoScheme() CryptoScheme {
	//	When the current TxVersion is updated due to crypto-scheme update, here the updated crypto-scheme is set.
	return CryptoSchemePQRingCTX
}

//	The mapping between TxVersion/TxoVersion/RingVersion/ and crypto-scheme	end

// GetNullSerialNumber() return the null serial number.
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
		return nil, errors.New("GetNullSerialNumber: Unsupported txVersion")
	}
}

// APIs providing params of underlying CryptoScheme		begin
// GetTxoSerializeSizeApprox returns the approximate serialize size for Txo, which is decided by the TxVersion.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for Txo actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
func GetTxoSerializeSizeApprox(txVersion uint32, cryptoAddress []byte) (int, error) {
	cryptoScheme, err := GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}
	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		return abecryptoparam.GetTxoSerializeSizeApprox(txVersion)
	case CryptoSchemePQRingCTX:
		return pqringctxGetTxoSerializeSizeApprox(PQRingCTXPP, cryptoAddress)
	default:
		return 0, errors.New("GetTxoSerializeSizeApprox: Unsupported txVersion")
	}
}

// GetCbTxWitnessSerializeSizeApprox returns the approximate serialize size for CoinbaseTxWitness, which is decided by the TxVersion and the number of out Txo.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for CoinbaseTxWitness actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
func GetCbTxWitnessSerializeSizeApprox(txVersion uint32, cryptoAddressListPayTo [][]byte) (int, error) {
	cryptoScheme, err := GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}
	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		return abecryptoparam.GetCbTxWitnessSerializeSizeApprox(txVersion, len(cryptoAddressListPayTo))
	case CryptoSchemePQRingCTX:
		if len(cryptoAddressListPayTo) == 0 {
			return 0, errors.New("GetCbTxWitnessSerializeSizeApprox: the input cryptoAddressListPayTo is empty")
		}
		coinAddressListPayTo := make([][]byte, len(cryptoAddressListPayTo))
		for i := 0; i < len(cryptoAddressListPayTo); i++ {
			//	Note that the cryptoAddressListPayTo[i] may not be generated by pqringctx,
			//	we call ParseCryptoAddress() to cover all cases.
			_, coinAddress, _, err := CryptoAddressParse(cryptoAddressListPayTo[i])
			if err != nil {
				return 0, err
			}
			coinAddressListPayTo[i] = coinAddress
		}
		return pqringctxGetCbTxWitnessSerializeSizeApprox(PQRingCTXPP, coinAddressListPayTo)
	default:
		return 0, errors.New("GetCbTxWitnessSerializeSizeApprox: Unsupported txVersion")
	}
}

// APIs providing params of underlying CryptoScheme		end

//	APIs for AddressKey-Encode-Format	begin
//
// ExtractCryptoSchemeFromCryptoAddress extracts cryptoScheme from cryptoAddress.
func ExtractCryptoSchemeFromCryptoAddress(cryptoAddress []byte) (cryptoScheme CryptoScheme, err error) {
	if len(cryptoAddress) < 4 {
		errStr := fmt.Sprintf("ExtractCryptoSchemeFromCryptoAddress: incorrect length of cryptoAddress: %d", len(cryptoAddress))
		return 0, errors.New(errStr)
	}

	//	Note that in both PQRingCT and PQRingCTX, the first 4 bytes of CryptoAddress is serialization of the crypto-scheme
	cryptoScheme, err = DeserializeCryptoScheme(cryptoAddress[:4])
	if err != nil {
		return 0, err
	}

	return cryptoScheme, err
}

// ExtractPrivacyLevelFromCryptoAddress extracts privacyLevel from cryptoAddress
func ExtractPrivacyLevelFromCryptoAddress(cryptoScheme CryptoScheme, cryptoAddress []byte) (privacyLevel PrivacyLevel, err error) {
	cryptoSchemeInAddress, err := ExtractCryptoSchemeFromCryptoAddress(cryptoAddress)
	if err != nil {
		return 0, err
	}

	if cryptoSchemeInAddress != cryptoScheme {
		errStr := fmt.Sprintf("ExtractPrivacyLevelFromCryptoAddress: extracted CryptoScheme %d does not match the input CryptoScheme %d", cryptoSchemeInAddress, cryptoScheme)
		return 0, errors.New(errStr)
	}

	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		//	this is to achieve back-compatibility with PQRingCT
		_, _, err := abecryptoparam.CryptoAddressParse(cryptoAddress)
		if err != nil {
			return 0, err
		}
		privacyLevel = PrivacyLevelRINGCTPre

	case CryptoSchemePQRingCTX:
		privacyLevel, _, _, err = pqringctxCryptoAddressParse(PQRingCTXPP, cryptoScheme, cryptoAddress)
		if err != nil {
			return 0, err
		}

	default:
		return 0, errors.New("ExtractPrivacyLevelFromCryptoAddress: unsupported crypto-scheme")
	}

	return privacyLevel, nil
}

// CryptoAddressParse could be used to parse the CryptoAddress to the corresponding coinAddress, and valuePublicKey, as well as its privacyLevel.
// Note that the input CryptoAddress should be ones generated by CryptoAddressKeyGen (of different underlying crypto-schemes) and encoded by the unifrom rule,
// namely, the first 4 bytes is the encoded CryptoScheme, under which the cryptoAddress was generated.
func CryptoAddressParse(cryptoAddress []byte) (privacyLevel PrivacyLevel,
	coinAddress []byte,
	valuePublicKey []byte,
	err error) {
	cryptoScheme, err := ExtractCryptoSchemeFromCryptoAddress(cryptoAddress)
	if err != nil {
		return 0, nil, nil, err
	}

	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		//	this is to achieve back-compatibility with PQRingCT
		coinAddress, valuePublicKey, err = abecryptoparam.CryptoAddressParse(cryptoAddress)
		if err != nil {
			return 0, nil, nil, err
		}
		privacyLevel = PrivacyLevelRINGCTPre

	case CryptoSchemePQRingCTX:
		privacyLevel, coinAddress, valuePublicKey, err = pqringctxCryptoAddressParse(PQRingCTXPP, cryptoScheme, cryptoAddress)
		if err != nil {
			return 0, nil, nil, err
		}

	default:
		return 0, nil, nil, errors.New("ExtractPrivacyLevelFromCryptoAddress: unsupported crypto-scheme")
	}

	return privacyLevel, coinAddress, valuePublicKey, nil

}

//	APIs for AddressKey-Encode-Format	end

// API for Sizes	begin

// GetCryptoSchemeParamSeedBytesLen returns the ParamSeedBytesLen for the input param cryptoScheme.
// The caller may call this API to obtain the ParamSeedBytesLen for the input param cryptoScheme,
// then prepare randSeed for CryptoAddressKeyGen().
func GetCryptoSchemeParamSeedBytesLen(cryptoScheme CryptoScheme) (int, error) {
	switch cryptoScheme {
	case CryptoSchemePQRingCT:
		//	this is to achieve back-compatibility with PQRingCT
		return abecryptoparam.GetCryptoSchemeParamSeedBytesLen(abecryptoparam.CryptoSchemePQRingCT)

	case CryptoSchemePQRingCTX:
		return pqringctxGetCryptoSchemeParamSeedBytesLen(PQRingCTXPP), nil

	default:
		return 0, errors.New("CryptoAddressKeyGen: unsupported crypto-scheme")
	}

	return 0, nil
}

// API for Sizes	end
