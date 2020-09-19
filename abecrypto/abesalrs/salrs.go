package abesalrs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/cryptosuite/salrs-go/salrs"
)

var MpkByteLen = salrs.MpkByteLen
var DpkByteLen = salrs.DpkByteLen
var MsskByteLen = salrs.MsskByteLen
var MsvkByteLen = salrs.MsvkByteLen

type MasterPubKey salrs.MasterPubKey
type MasterSecretViewKey salrs.MasterSecretViewKey
type MasterSecretSignKey salrs.MasterSecretSignKey
type DerivedPubKey salrs.DerivedPubKey
type Signature salrs.Signature
type KeyImage salrs.KeyImage
type DpkRing struct {
	Dpks []DerivedPubKey
	R    int
}
const (
	RecommendedSeedLen = 32
	MinSeedBytes       = 16
	MaxSeedBytes       = 64
	maxUint8           = 1<<8 - 1
)

var (
	ErrInvalidSeedLen = fmt.Errorf("seed length must be between %d and %d "+
		"bits", MinSeedBytes*8, MaxSeedBytes*8)
)

func GenerateSeed(length uint8) ([]byte, error) {
	if length < MinSeedBytes || length > MaxSeedBytes {
		return nil, ErrInvalidSeedLen
	}
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil

}
func GenerateMasterKey(seed []byte) (*MasterPubKey, *MasterSecretViewKey, *MasterSecretSignKey, []byte, error) {
	var emptySeed bool
	if seed == nil || len(seed) == 0 {
		emptySeed = true
	}
	if len(seed) < MinSeedBytes || len(seed) > MaxSeedBytes {
		return nil, nil, nil, nil, ErrInvalidSeedLen
	}
	if emptySeed {
		mseed := make([]byte, RecommendedSeedLen)
		mseed, err := GenerateSeed(RecommendedSeedLen)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		seed = mseed[:]
	}
	mpk, msvk, mssk, _, err := salrs.GenerateMasterKey(seed)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if emptySeed {
		return (*MasterPubKey)(mpk), (*MasterSecretViewKey)(msvk), (*MasterSecretSignKey)(mssk), seed, nil
	}
	return (*MasterPubKey)(mpk), (*MasterSecretViewKey)(msvk), (*MasterSecretSignKey)(mssk), nil, nil
}

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
	if len(mpkSerialized) != MpkByteLen {
		return nil, errors.New("length of serialzed mpk bytes is wrong")
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
	if len(dpkSerialzed) != DpkByteLen {
		return nil, errors.New("length of serialzed dpk bytes is wrong")
	}

	salrsderivedPubKey, salrserr := salrs.DeseralizeDerivedPubKey(dpkSerialzed)
	if salrserr != nil {
		return nil, salrserr
	}

	derivedPubKey := (*DerivedPubKey)(salrsderivedPubKey)

	return derivedPubKey, nil
}

func (msvk *MasterSecretViewKey) Serialize() []byte {
	b := msvk.toSALRS().Serialize()
	return b
}

func DeseralizeMasterSecretViewKey(b []byte) (msvk *MasterSecretViewKey, err error) {
	if len(b) == 0 {
		return nil, errors.New("serialzed msvk bytes are empty")
	}
	if len(b) != MsvkByteLen {
		return nil, errors.New("length of serialzed msvk bytes is wrong")
	}
	msvksalrs, err := salrs.DeseralizeMasterSecretViewKey(b)
	if err != nil {
		return nil, err
	}
	msvk = (*MasterSecretViewKey)(msvksalrs)

	return msvk, nil
}

func (mssk *MasterSecretSignKey) Serialize() []byte {
	b := mssk.toSALRS().Serialize()
	return b
}

func DeseralizeMasterSecretSignKey(b []byte) (mssk *MasterSecretSignKey, err error) {
	if len(b) == 0 {
		return nil, errors.New("serialzed mssk bytes are empty")
	}
	if len(b) != MsskByteLen {
		return nil, errors.New("length of serialzed mssk bytes is wrong")
	}
	salrsmssk, err := salrs.DeseralizeMasterSecretSignKey(b)
	if err != nil {
		return nil, err
	}
	mssk = (*MasterSecretSignKey)(salrsmssk)
	return mssk, nil
}

// TODO(abe): actually these two function can be substitute by type convertion
//	private filed 	begin
func (mpk *MasterPubKey) toSALRS() *salrs.MasterPubKey {
	return (*salrs.MasterPubKey)(mpk)
}

func (dpk *DerivedPubKey) toSALRS() *salrs.DerivedPubKey {
	return (*salrs.DerivedPubKey)(dpk)
}
func (msvk *MasterSecretViewKey) toSALRS() *salrs.MasterSecretViewKey {
	return (*salrs.MasterSecretViewKey)(msvk)
}
func (mssk *MasterSecretSignKey) toSALRS() *salrs.MasterSecretSignKey {
	return (*salrs.MasterSecretSignKey)(mssk)
}
func (sig *Signature) toSALRS() *salrs.Signature {
	return (*salrs.Signature)(sig)
}
func (k *KeyImage) toSALRS() *salrs.KeyImage {
	return (*salrs.KeyImage)(k)
}
// TODO(abe): abstract the check function, not for just one crypto scheme one check
func CheckDerivedPubKeyAttribute(dpk *DerivedPubKey,mpk *MasterPubKey,msvk *MasterSecretViewKey) (bool,error) {
	return salrs.CheckDerivedPubKeyOwner(dpk.toSALRS(),mpk.toSALRS(),msvk.toSALRS())
}
func Sign(msg []byte, dpkRing *DpkRing, dpk *DerivedPubKey, mpk *MasterPubKey, msvk *MasterSecretViewKey, mssk *MasterSecretSignKey) (sig *Signature, err error) {
	dpkRingSalrs:=new(salrs.DpkRing)
	dpkRingSalrs.R=dpkRing.R
	for i:=0;i<dpkRing.R;i++{
		dpkRingSalrs.Dpk=append(dpkRingSalrs.Dpk,*dpkRing.Dpks[i].toSALRS())
	}
	signature, err := salrs.Sign(msg, dpkRingSalrs, dpk.toSALRS(), mpk.toSALRS(), msvk.toSALRS(), mssk.toSALRS())
	if err!=nil{
		return nil,err
	}
	return (*Signature)(signature),nil
}
func Verify(msg []byte, dpkRing *DpkRing,sig *Signature)(*KeyImage,bool,error){
	dpkRingSalrs:=new(salrs.DpkRing)
	dpkRingSalrs.R=dpkRing.R
	for i:=0;i<dpkRing.R;i++{
		dpkRingSalrs.Dpk=append(dpkRingSalrs.Dpk,*dpkRing.Dpks[i].toSALRS())
	}
	k, b,err := salrs.Verify(msg, dpkRingSalrs, sig.toSALRS())
	return (*KeyImage)(k),b,err
}
func Check(msg1 []byte, dpkRing1 *DpkRing, sig1 *Signature, msg2 []byte, dpkRing2 *DpkRing, sig2 *Signature) (bool,error){
	dpkRingSalrs1:=new(salrs.DpkRing)
	dpkRingSalrs1.R=dpkRing1.R
	for i:=0;i<dpkRing1.R;i++{
		dpkRingSalrs1.Dpk=append(dpkRingSalrs1.Dpk,*dpkRing1.Dpks[i].toSALRS())
	}
	dpkRingSalrs2:=new(salrs.DpkRing)
	dpkRingSalrs2.R=dpkRing2.R
	for i:=0;i<dpkRing2.R;i++{
		dpkRingSalrs2.Dpk=append(dpkRingSalrs2.Dpk,*dpkRing2.Dpks[i].toSALRS())
	}
	return salrs.Link(msg1, dpkRingSalrs1,sig1.toSALRS(), msg2,dpkRingSalrs2,sig2.toSALRS())
}
func (s *Signature)Serialize()[]byte{
	return s.toSALRS().Serialize()
}
func DeserializeSignature(b []byte)(*Signature,error){
	s,err:=salrs.DeserializeSignature(b)
	if err!=nil{
		return nil,err
	}
	return (*Signature)(s), nil
}
func (k *KeyImage)Serialize()[]byte{
	return k.toSALRS().Serialize()
}
func DeserializeKeyImage(b []byte)(*KeyImage,error){
	r,err:=salrs.DeserializeKeyImage(b)
	if err!=nil{
		return nil,err
	}
	return (*KeyImage)(r),nil
}
//	private field	end
