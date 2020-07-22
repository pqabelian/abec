package abesalrs

import (
	"errors"
	"github.com/cryptosuite/salrs-go/salrs"
)

var MpkByteLen = salrs.MpkByteLen
var DpkByteLen = salrs.DpkByteLen

type MasterPubKey salrs.MasterPubKey
type DerivedPubKey salrs.DerivedPubKey

func GenerateDerivedPubKey(mpk *MasterPubKey) (dpk *DerivedPubKey, err error) {
	if mpk == nil {
		return nil, errors.New("mpk is nil")
	}

	salrsderivedPubKey, salrserr := salrs.GenerateDerivedPubKey(mpk.toSALRS())
	if salrserr != nil {
		return nil, salrserr
	}

	derivedPubKey := (*DerivedPubKey)(salrsderivedPubKey)

	return derivedPubKey, nil
}

func (mpk *MasterPubKey) Serialize() []byte {
	b := mpk.toSALRS().Serialize()
	return b
}

func DeseralizeMasterPubKey(mpkSerialized []byte) (mpk *MasterPubKey, err error) {
	if len(mpkSerialized) == 0 {
		return nil, errors.New("serialzed mpk bytes are empty")
	}

	salrsmasterPubKey, salrserr := salrs.DeseralizeMasterPubKey(mpkSerialized)
	if salrserr != nil {
		return nil, salrserr
	}
	masterPubKey := (*MasterPubKey)(salrsmasterPubKey)

	return masterPubKey, nil

}

func (dpk *DerivedPubKey) Serialize() []byte {
	b := dpk.toSALRS().Serialize()
	return b
}

func DeseralizeDerivedPubKey(dpkSerialzed []byte) (dpk *DerivedPubKey, err error) {
	if len(dpkSerialzed) == 0 {
		return nil, errors.New("serialzed dpk bytes are empty")
	}

	salrsderivedPubKey, salrserr := salrs.DeseralizeDerivedPubKey(dpkSerialzed)
	if salrserr != nil {
		return nil, salrserr
	}

	derivedPubKey := (*DerivedPubKey)(salrsderivedPubKey)

	return derivedPubKey, nil
}

//	private filed 	begin
func (mpk *MasterPubKey) toSALRS() *salrs.MasterPubKey {
	return (*salrs.MasterPubKey)(mpk)
}

func (dpk *DerivedPubKey) toSALRS() *salrs.DerivedPubKey {
	return (*salrs.DerivedPubKey)(dpk)
}

//	private field	end
