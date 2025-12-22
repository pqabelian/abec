package abecryptoxparam

import (
	"github.com/cryptosuite/pqringctx/pqringctxapi"
)

// API for Sizes	begin
// reviewed on 2023.12.07
func pqringctxGetCryptoSchemeParamSeedBytesLen(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetParamSeedBytesLen(pp)
}
func pqringctxGetParamKeyGenPublicRandBytesLen(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetParamKeyGenPublicRandBytesLen(pp)
}

//	API for Sizes	end

//	Transaction-related Params	begin

// pqringctxGetSerialNumberSerialSize
// todo: review
func pqringctxGetSerialNumberSerializeSize(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetSerialNumberSerializeSize(pp)
}

// GetNullSerialNumber() return the null serial number.
// reviewed on 2023.12.07
func pqringctxGetNullSerialNumber(pp *pqringctxapi.PublicParameter) []byte {
	return pqringctxapi.GetNullSerialNumber(pp)
}

// pqringctxGetTxoScriptSize returns the TxoSerializeSize for the input coinAddressPayTo.
// reviewed on 2023.12.07
// We have a design that pqringctx-Layer takes as input cryptoAddress and parses it to coinAddress,
// however, this function may cause cyclic imports. As a result, we have to use coinAddress here as input.
// ctx review done 2025.12.22
func pqringctxGetTxoScriptSize(pp *pqringctxapi.PublicParameter, coinAddressPayTo []byte) (int, error) {
	return pqringctxapi.GetTxoSerializeSize(pp, coinAddressPayTo)
}

// pqringctxGetTxInputMaxNum returns the allowed maximum number of TxInputs.
// reviewed on 2024.01.03
func pqringctxGetTxInputMaxNum(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetTxInputMaxNum(pp)
}

func pqringctxGetTxInputMaxNumForRing(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetTxInputMaxNumForRing(pp)
}

func pqringctxGetTxInputMaxNumForSingle(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetTxInputMaxNumForSingle(pp)
}

// pqringctxGetTxOutputMaxNum returns the allowed maximum number of TxOutputs.
// reviewed on 2024.01.03
func pqringctxGetTxOutputMaxNum(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetTxOutputMaxNum(pp)
}

func pqringctxGetTxOutputMaxNumForRing(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetTxOutputMaxNumForRing(pp)
}

func pqringctxGetTxOutputMaxNumForSingle(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetTxOutputMaxNumForSingle(pp)
}

//	Transaction-related Params	end

// ctx review done 2025.12.22
