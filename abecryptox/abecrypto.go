package abecryptox

import (
	"errors"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/wire"
)

// CryptoAddressKeyGen generates cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk from the param randSeed.
// The param randSeed is a randomness that will be used to in randomized algorithms to make the algorithms be deterministic to the caller.
// The caller should make sure that randSeed is random and have sufficient entropy.
// (1) For the case of privacyLevel == abecryptoxparam.PrivacyLevelRINGCT, randSeed should have size of TWO times of CryptoScheme's ParamSeedBytesLen (in bytes), one for address and one for value-privacy.
// (2) For the case of privacyLevel == abecryptoxparam.PrivacyLevelPSEUDONYM, randSeed should have size of CryptoScheme's ParamSeedBytesLen (in bytes), which is used to address.
// (Note that CryptoScheme's ParamSeedBytesLen could be obtained by GetCryptoSchemeParamSeedBytesLen().)
// Accordingly,
// for the case of privacyLevel == abecryptoxparam.PrivacyLevelPSEUDONYM, cryptoSnsk and cryptoVsk will be nil.
func CryptoAddressKeyGen(randSeed []byte, cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel abecryptoxparam.PrivacyLevel) (retCryptoAddress []byte, retCryptoSpsk []byte, retCryptoSnsk []byte, retCryptoVsk []byte, err error) {
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		// This is to achieve back-compatibility with CryptoSchemePQRingCT.
		// The caller, e.g., the wallet created with CryptoSchemePQRingCT will still call this function with cryptoScheme=CryptoSchemePQRingCT.
		return abecrypto.CryptoAddressKeyGen(randSeed, abecryptoparam.CryptoSchemePQRingCT)

	case abecryptoxparam.CryptoSchemePQRingCTX:
		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, err := pqringctxCryptoAddressKeyGen(abecryptoxparam.PQRingCTXPP, randSeed, cryptoScheme, privacyLevel)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil

	default:
		return nil, nil, nil, nil, errors.New("CryptoAddressKeyGen: unsupported crypto-scheme")
	}
	//return nil, nil, nil, nil, nil
}

func CoinbaseTxGen(abeTxOutputDescs []*AbeTxOutputDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(coinbaseTxMsgTemplate.Version)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		// This is to achieve back-compatibility with CryptoSchemePQRingCT.
		// Before the BlockHeightMLP, the caller may use the coinbaseTxMsgTemplate.Version that maps to CryptoSchemePQRingCT.
		pqRingCTAbeTxOutputDescs := make([]*abecrypto.AbeTxOutputDesc, len(abeTxOutputDescs))
		for i := 0; i < len(abeTxOutputDescs); i++ {
			pqRingCTAbeTxOutputDescs[i] = abecrypto.NewAbeTxOutDesc(abeTxOutputDescs[i].cryptoAddress, abeTxOutputDescs[i].value)
		}

		cbTx, err := abecrypto.CoinbaseTxGen(pqRingCTAbeTxOutputDescs, coinbaseTxMsgTemplate)
		if err != nil {
			return nil, err
		}
		return cbTx, nil

	case abecryptoxparam.CryptoSchemePQRingCTX:
		cbTx, err := pqringctxCoinbaseTxGen(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxOutputDescs, coinbaseTxMsgTemplate)
		if err != nil {
			return nil, err
		}
		return cbTx, nil
	default:
		return nil, errors.New("CoinbaseTxGen: Unsupported crypto scheme")
	}

}

//	APIs for AddressKey-Encode-Format	begin
//	APIs for AddressKey-Encode-Format	end
