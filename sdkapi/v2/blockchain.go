package v2

import "github.com/abesuite/abec/wire"

func GetTxoRingSizeByBlockHeight(height int32) uint8 {
	return wire.GetTxoRingSizeByBlockHeight(height)
}

func GetBlockNumPerRingGroupByBlockHeight(height int32) uint8 {
	return wire.GetBlockNumPerRingGroupByBlockHeight(height)
}
