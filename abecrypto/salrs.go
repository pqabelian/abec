package abecrypto

import (
	"errors"
	"github.com/cryptosuite/salrs-go/salrs"
)

const MpkByteLen = salrs.MpkByteLen
const DpkByteLen = salrs.DpkByteLen

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

func DeseralizeMasterPubKey(mpkByteStr []byte) (mpk *MasterPubKey, err error) {
	if len(mpkByteStr) == 0 {
		return nil, errors.New("mpk byte string is empty")
	}

	salrsmasterPubKey, salrserr := salrs.DeseralizeMasterPubKey(mpkByteStr)
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

func DeseralizeDerivedPubKey(dpkByteStr []byte) (dpk *DerivedPubKey, err error) {
	if len(dpkByteStr) == 0 {
		return nil, errors.New("dpk byte string is empty")
	}

	salrsderivedPubKey, salrserr := salrs.DeseralizeDerivedPubKey(dpkByteStr)
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
