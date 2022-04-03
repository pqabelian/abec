package abeutil

const (
	// SatoshiPerBitcent is the number of satoshi in one bitcoin cent.
	SatoshiPerBitcent = 1e6

	// SatoshiPerBitcoin is the number of satoshi in one bitcoin (1 BTC).
	SatoshiPerBitcoin = 1e8

	// MaxSatoshi is the maximum transaction amount allowed in satoshi.
	MaxSatoshi = 21e6 * SatoshiPerBitcoin
)

const (
	// SatoshiPerBitcent is the number of satoshi in one bitcoin cent.
	//	SatoshiPerBitcent = 1e6

	//	todo: 20220327 Denote the value by uint64
	// NeutrinoPerAbe is the number of Neutrino in one Abe (1 ABE).
	NeutrinoPerAbe = 1e7

	// MaxAbe is the maximum transaction amount allowed in Neutrino.
	MaxAbe = 1<<51 - 1

	// MaxNeutrino is the maximum transaction amount allowed in Neutrino.
	MaxNeutrino = 296e6 * NeutrinoPerAbe
)
