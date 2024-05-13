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

// pqringctxGetTxoSerializeSize
// todo: review
func pqringctxGetTxoSerializeSize(pp *pqringctxapi.PublicParameter, coinAddressPayTo []byte) (int, error) {
	return pqringctxapi.GetTxoSerializeSize(pp, coinAddressPayTo)
}

// pqringctxGetTxInputMaxNum returns the allowed maximum number of TxInputs.
// reviewed on 2024.01.03
func pqringctxGetTxInputMaxNum(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetTxInputMaxNum(pp)
}

// pqringctxGetTxOutputMaxNum returns the allowed maximum number of TxOutputs.
// reviewed on 2024.01.03
func pqringctxGetTxOutputMaxNum(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetTxOutputMaxNum(pp)
}

//	Transaction-related Params	end
