package api

import (
	"bytes"
	"fmt"
	"math"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/ctaut/extscript"
	"github.com/abesuite/abec/ctaut/rules"
	"github.com/abesuite/abec/ctaut/script"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
)

// Create:
// 1. NewXXXAutScript
// 2. PackageAutScript
// 3. write to TxMemo

// Use:
// 1. DetectAndAssembleExtAutScriptFromHostTx, which call unpackageAutScript as a subroutine

// New Functions	begin

func NewRegistrationScript(version uint32,
	autName []byte, autSymbol []byte, baseUnitName []byte, subUnitName []byte, unitScale uint64,
	autMemo []byte, plannedTotalSupply uint64,
	issuers []*AutIssuer, reregistrationExpireHeight int32, reregisterThreshold uint8, mintThreshold uint8,
	privacyType AutPrivacyType,
	outStarIndex uint8, outAutRootTokenNum uint8,
	scriptMemo []byte) *RegistrationScript {
	return script.NewRegistrationScript(version,
		autName, autSymbol, baseUnitName, subUnitName, unitScale,
		autMemo, plannedTotalSupply,
		issuers, reregistrationExpireHeight, reregisterThreshold, mintThreshold,
		privacyType,
		outStarIndex, outAutRootTokenNum,
		scriptMemo)
}

func NewReRegistrationScript(version uint32,
	autIdentifier AutId,
	autMemo []byte, plannedTotalSupply uint64,
	issuers []*AutIssuer, reregistrationExpireHeight int32, reregisterThreshold uint8, mintThreshold uint8,
	privacyType AutPrivacyType,
	inStartIndex uint8, inAutRootTokenNum uint8,
	outStartIndex uint8, outAutRootTokenNum uint8,
	scriptMemo []byte) *ReRegistrationScript {

	return script.NewReRegistrationScript(version,
		autIdentifier,
		autMemo, plannedTotalSupply,
		issuers, reregistrationExpireHeight, reregisterThreshold, mintThreshold,
		privacyType,
		inStartIndex, inAutRootTokenNum,
		outStartIndex, outAutRootTokenNum,
		scriptMemo)
}

func NewMintScript(version uint32,
	autIdentifier AutId,
	vin uint64,
	inStartIndex uint8, inAutRootTokenNum uint8,
	outStartIndex uint8, outCTAutTokenNum uint8, outPlainAutTokenNum uint8,
	serializedAutTxos [][]byte,
	scriptMemo []byte,
	witnessHash chainhash.Hash) *MintScript {

	return script.NewMintScript(version,
		autIdentifier,
		vin,
		inStartIndex, inAutRootTokenNum,
		outStartIndex, outCTAutTokenNum, outPlainAutTokenNum,
		serializedAutTxos,
		scriptMemo,
		witnessHash)
}

func NewTransferScript(version uint32,
	autIdentifier AutId,
	inStartIndex uint8, inHiddenAutTokenNum uint8, inPublicAutTokenNum uint8,
	outStartIndex uint8, outHiddenAutTokenNum uint8, outPublicAutTokenNum uint8,
	serializedAutTxos [][]byte,
	scriptMemo []byte,
	witnessHash chainhash.Hash) *TransferScript {

	return script.NewTransferScript(version,
		autIdentifier,
		inStartIndex, inHiddenAutTokenNum, inPublicAutTokenNum,
		outStartIndex, outHiddenAutTokenNum, outPublicAutTokenNum,
		serializedAutTxos,
		scriptMemo,
		witnessHash)
}

func NewBurnScript(version uint32,
	autIdentifier AutId,
	inStartIndex uint8, inHiddenAutTokenNum uint8, inPublicAutTokenNum uint8,
	outStartIndex uint8, outHiddenAutTokenNum uint8, outPublicAutTokenNum uint8, serializedAutTxos [][]byte,
	scriptMemo []byte,
	witnessHash chainhash.Hash) *BurnScript {

	return script.NewBurnScript(version,
		autIdentifier,
		inStartIndex, inHiddenAutTokenNum, inPublicAutTokenNum,
		outStartIndex, outHiddenAutTokenNum, outPublicAutTokenNum, serializedAutTxos,
		scriptMemo,
		witnessHash)
}

// New Functions	end

// PackageAutScript packages an AutScript to a packagedAutScript, where
// packagedAutScript = commonPrefix (="AUTSCRIPT") || version (in VarInt form) || serializedAutScript (in VarBytes form).
func PackageAutScript(autScript AutScript) (packagedAutScript []byte, err error) {

	serializedScript, err := autScript.Serialize()
	if err != nil {
		return nil, err
	}

	length := len([]byte(commonPrefix))
	length += wire.VarIntSerializeSize(uint64(autScript.Version()))

	length += wire.VarIntSerializeSize(uint64(len(serializedScript))) + len(serializedScript)

	w := bytes.NewBuffer(make([]byte, 0, length))

	_, err = w.Write([]byte(commonPrefix))
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(w, 0, uint64(autScript.Version()))
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(w, 0, serializedScript)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// unpackageAutScript unpackages a packagedAutScript to an AutScript, where packagedAutScript is assumed to start from
// commonPrefix (="AUTSCRIPT") || version (in VarInt form) || serializedAutScript (in VarBytes form).
// A packagedAutScript does not satisfy this form will result an error returned.
func unpackageAutScript(packagedAutScript []byte) (AutScript, error) {
	commonPrefixLen := len([]byte(commonPrefix))
	if len(packagedAutScript) < commonPrefixLen {
		return nil, fmt.Errorf("packagedAutScript is not well-form as expected")
	}

	if !bytes.Equal(packagedAutScript[:commonPrefixLen], []byte(commonPrefix)) {
		return nil, fmt.Errorf("packagedAutScript is not well-form as expected: not start with %s", commonPrefix)
	}

	r := bytes.NewReader(packagedAutScript[commonPrefixLen:])
	versionRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}
	if versionRead > math.MaxUint32 {
		return nil, fmt.Errorf("read script version (%d) is too large", versionRead)
	}
	scriptVersion := uint32(versionRead)
	if _, ok := ctautwire.AutScriptVersionSet[scriptVersion]; !ok {
		return nil, fmt.Errorf("unknown version %d", scriptVersion)
	}

	serializedScript, err := wire.ReadVarBytes(r, 0, script.MaxAutScriptLength, "AutScript")
	if err != nil {
		return nil, err
	}

	// todo: if multiple versions are supported, may need to code here to run different branch
	switch scriptVersion {
	case ctautwire.AutScriptVersion_1:
		return script.DeserializeAutScriptV1(serializedScript)

	default:
		return nil, fmt.Errorf("unknown aut script version %d", scriptVersion)
	}
}

// DetectAndAssembleExtAutScriptFromHostTx is the only entrance for generating ExtAutScript.
//
// NOTE: only outputTokens of ExtAutScript are assembled.
func DetectAndAssembleExtAutScriptFromHostTx(msgTx *wire.MsgTxAbe) (*ExtAutScript, error) {
	if msgTx == nil {
		return nil, fmt.Errorf("DetectAndAssembleExtAutScriptFromHostTx: msgTx is nil")
	}

	if msgTx.Version < wire.TxVersion_Height_464000_Aconcagua {
		return nil, nil
	}
	isCoinbase, err := msgTx.IsCoinBase()
	if err != nil {
		return nil, fmt.Errorf("DetectAndAssembleExtAutScriptFromHostTx: error happens when calling msgTx.IsCoinBase() : %v", err)
	}
	if isCoinbase {
		return nil, nil
	}

	// detect and extract aut script from TxMemo and check well-formedness
	commonPrefixLen := len([]byte(commonPrefix))

	// could not be an AUT transaction
	if len(msgTx.TxMemo) < commonPrefixLen {
		return nil, nil
	}
	if !bytes.Equal(msgTx.TxMemo[:commonPrefixLen], []byte(commonPrefix)) {
		return nil, nil
	}

	// RULE: if commonPrefix appears, the commonPrefix and its following bytes must be a well-formed packagedAutScript,
	// namely, commonPrefix || Version(in VarInt form) || serializedAutScript (in VarBytes form).
	autScript, err := unpackageAutScript(msgTx.TxMemo)
	if err != nil {
		return nil, err
	}

	// conduct some sanity-checks on autScript 		BEGIN
	// 1. expectedTxVersion
	// 2. autWitnessHash

	// check the script version with the host-txo version
	expectedTxVersion, err := rules.RuleGetTxVersionFromAutScriptVersion(autScript.Version())
	if err != nil {
		return nil, fmt.Errorf("DetectAndAssembleExtAutScriptFromHostTx: error happens when calling RuleGetTxVersionFromAutScriptVersion() : %v", err)
	}
	if expectedTxVersion != msgTx.Version {
		return nil, fmt.Errorf("autScript.Version() (%d) corresponds to TxVersion (%d), does not match TxVersion %d",
			autScript.Version(), expectedTxVersion, msgTx.Version)
	}

	autWitnessHashInScript := autScript.WitnessHash()
	switch autScriptInst := autScript.(type) {
	case *RegistrationScript:
		// no input

		// output
		outStartIndex := autScriptInst.OutStartIndex()
		outAutRootTokenNum := autScriptInst.OutAutRootTokenNum()

		if int(outStartIndex)+int(outAutRootTokenNum) > len(msgTx.TxOuts) {
			return nil, fmt.Errorf("outStartIndex (%d) + outAutRootTokenNum (%d) exceeds the number of TxOuts (%d)",
				outStartIndex, outAutRootTokenNum, len(msgTx.TxOuts))
		}
		if int(outStartIndex)+int(outAutRootTokenNum) > math.MaxUint8 {
			// This is redundant, since a valid Tx will have len(msgTx.TxOuts) < 255
			return nil, fmt.Errorf("outStartIndex (%d) + outAutRootTokenNum (%d) exceeds allowed maximum value %d",
				outStartIndex, outAutRootTokenNum, math.MaxUint8)
		}
		break

	case *ReRegistrationScript:
		inStartIndex := autScriptInst.InStartIndex()
		inAutRootTokenNum := autScriptInst.InAutRootTokenNum()

		if int(inStartIndex)+int(inAutRootTokenNum) > len(msgTx.TxIns) {
			return nil, fmt.Errorf("inStartIndex (%d) + inAutRootTokenNum (%d) exceeds the number of TxIns (%d)",
				inStartIndex, inAutRootTokenNum, len(msgTx.TxIns))
		}
		if int(inStartIndex)+int(inAutRootTokenNum) > math.MaxUint8 {
			// This is redundant, since a valid Tx will have len(msgTx.TxIns) < 255
			return nil, fmt.Errorf("inStartIndex (%d) + inAutRootTokenNum (%d) exceeds allowed maximum value %d",
				inStartIndex, inAutRootTokenNum, math.MaxUint8)
		}

		outStartIndex := autScriptInst.OutStartIndex()
		outAutRootTokenNum := autScriptInst.OutAutRootTokenNum()

		if int(outStartIndex)+int(outAutRootTokenNum) > len(msgTx.TxOuts) {
			return nil, fmt.Errorf("outStartIndex (%d) + outAutRootTokenNum (%d) exceeds the number of TxOuts (%d)",
				outStartIndex, outAutRootTokenNum, len(msgTx.TxOuts))
		}
		if int(outStartIndex)+int(outAutRootTokenNum) > math.MaxUint8 {
			// This is redundant, since a valid Tx will have len(msgTx.TxOuts) < 255
			return nil, fmt.Errorf("outStartIndex (%d) + outAutRootTokenNum (%d) exceeds allowed maximum value",
				outStartIndex, outAutRootTokenNum)
		}

		break

	case *MintScript:
		inStartIndex := autScriptInst.InStartIndex()
		inAutRootTokenNum := autScriptInst.InAutRootTokenNum()

		if int(inStartIndex)+int(inAutRootTokenNum) > len(msgTx.TxIns) {
			return nil, fmt.Errorf("inStartIndex (%d) + inAutRootTokenNum (%d) exceeds the number of TxIns (%d)",
				inStartIndex, inAutRootTokenNum, len(msgTx.TxIns))
		}
		if int(inStartIndex)+int(inAutRootTokenNum) > math.MaxUint8 {
			// This is redundant, since a valid Tx will have len(msgTx.TxIns) < 255
			return nil, fmt.Errorf("inStartIndex (%d) + inAutRootTokenNum (%d) exceeds allowed maximum value",
				inStartIndex, inAutRootTokenNum)
		}

		outStartIndex := autScriptInst.OutStartIndex()
		outHiddenAutTokenNum := autScriptInst.OutHiddenAutTokenNum()
		outPublicAutTokenNum := autScriptInst.OutPublicAutTokenNum()

		if int(outStartIndex)+int(outHiddenAutTokenNum)+int(outPublicAutTokenNum) > len(msgTx.TxOuts) {
			// The Index in (TxHash, Index) is designed to be uint8.
			return nil, fmt.Errorf("outStartIndex (%d) + outHiddenAutTokenNum (%d) + outPublicAutTokenNum (%d) exceeds the number of TxOuts %d",
				outStartIndex, outHiddenAutTokenNum, outPublicAutTokenNum, len(msgTx.TxOuts))
		}
		if int(outStartIndex)+int(outHiddenAutTokenNum)+int(outPublicAutTokenNum) > math.MaxUint8 {
			// This is redundant, since a valid Tx will have len(msgTx.TxOuts) < 255
			return nil, fmt.Errorf("outStartIndex (%d) + outHiddenAutTokenNum (%d) + outPublicAutTokenNum (%d) exceeds allowed maximum value %d",
				outStartIndex, outHiddenAutTokenNum, outPublicAutTokenNum, math.MaxUint8)
		}

		if msgTx.HasAutWitness() {
			autWitnessHashComputed := ctautwire.AutWitnessHash(msgTx.AutWitness)
			if !autWitnessHashComputed.IsEqual(&autWitnessHashInScript) {
				return nil, fmt.Errorf("autWitnessHash computed from msgTx.AutWitness (%s) does not match "+
					"autScriptInst.AutWitnessHash (%s)", autWitnessHashComputed, autWitnessHashInScript)
			}
		}
		break

	case *TransferScript:
		inStartIndex := autScriptInst.InStartIndex()
		inHiddenAutTokenNum := autScriptInst.InHiddenAutTokenNum()
		inPublicAutTokenNum := autScriptInst.InPublicAutTokenNum()

		if int(inStartIndex)+int(inHiddenAutTokenNum)+int(inPublicAutTokenNum) > len(msgTx.TxIns) {
			return nil, fmt.Errorf("inStartIndex (%d) + inHiddenAutTokenNum (%d) + inPublicAutTokenNum(%d) exceeds the number of TxIns (%d)",
				inStartIndex, inHiddenAutTokenNum, inPublicAutTokenNum, len(msgTx.TxIns))
		}
		if int(inStartIndex)+int(inHiddenAutTokenNum)+int(inPublicAutTokenNum) > math.MaxUint8 {
			// This is redundant, since a valid Tx will have len(msgTx.TxIns) < 255
			return nil, fmt.Errorf("inStartIndex (%d) + inHiddenAutTokenNum (%d) + inPublicAutTokenNum(%d) exceeds allowed maximum value %d",
				inStartIndex, inHiddenAutTokenNum, inPublicAutTokenNum, math.MaxUint8)
		}

		outStartIndex := autScriptInst.OutStartIndex()
		outHiddenAutTokenNum := autScriptInst.OutHiddenAutTokenNum()
		outPublicAutTokenNum := autScriptInst.OutPublicAutTokenNum()

		if int(outStartIndex)+int(outHiddenAutTokenNum)+int(outPublicAutTokenNum) > len(msgTx.TxOuts) {
			// The Index in (TxHash, Index) is designed to be uint8.
			return nil, fmt.Errorf("outStartIndex (%d) + outHiddenAutTokenNum (%d) + outPublicAutTokenNum (%d) exceeds the number of TxOuts %d",
				outStartIndex, outHiddenAutTokenNum, outPublicAutTokenNum, len(msgTx.TxOuts))
		}
		if int(outStartIndex)+int(outHiddenAutTokenNum)+int(outPublicAutTokenNum) > math.MaxUint8 {
			// This is redundant, since a valid Tx will have len(msgTx.TxOuts) < 255
			return nil, fmt.Errorf("outStartIndex (%d) + outHiddenAutTokenNum (%d) + outPublicAutTokenNum (%d) exceeds allowed maximum value %d",
				outStartIndex, outHiddenAutTokenNum, outPublicAutTokenNum, math.MaxUint8)
		}

		if msgTx.HasAutWitness() {
			autWitnessHashComputed := ctautwire.AutWitnessHash(msgTx.AutWitness)
			if !autWitnessHashComputed.IsEqual(&autWitnessHashInScript) {
				return nil, fmt.Errorf("autWitnessHash computed from msgTx.AutWitness (%s) does not match "+
					"autScriptInst.AutWitnessHash (%s)", autWitnessHashComputed, autWitnessHashInScript)
			}
		}
		break

	case *BurnScript:
		inStartIndex := autScriptInst.InStartIndex()
		inHiddenAutTokenNum := autScriptInst.InHiddenAutTokenNum()
		inPublicAutTokenNum := autScriptInst.InPublicAutTokenNum()

		if int(inStartIndex)+int(inHiddenAutTokenNum)+int(inPublicAutTokenNum) > len(msgTx.TxIns) {
			return nil, fmt.Errorf("inStartIndex (%d) + inHiddenAutTokenNum (%d) + inPublicAutTokenNum(%d) exceeds the number of TxIns (%d)",
				inStartIndex, inHiddenAutTokenNum, inPublicAutTokenNum, len(msgTx.TxIns))
		}
		if int(inStartIndex)+int(inHiddenAutTokenNum)+int(inPublicAutTokenNum) > math.MaxUint8 {
			// This is redundant, since a valid Tx will have len(msgTx.TxIns) < 255
			return nil, fmt.Errorf("inStartIndex (%d) + inHiddenAutTokenNum (%d) + inPublicAutTokenNum(%d) exceeds allowed maximum value %d",
				inStartIndex, inHiddenAutTokenNum, inPublicAutTokenNum, math.MaxUint8)
		}

		outStartIndex := autScriptInst.OutStartIndex()
		outHiddenAutTokenNum := autScriptInst.OutHiddenAutTokenNum()
		outPublicAutTokenNum := autScriptInst.OutPublicAutTokenNum()

		if int(outStartIndex)+int(outHiddenAutTokenNum)+int(outPublicAutTokenNum) > len(msgTx.TxOuts) {
			// The Index in (TxHash, Index) is designed to be uint8.
			return nil, fmt.Errorf("outStartIndex (%d) + outHiddenAutTokenNum (%d) + outPublicAutTokenNum (%d) exceeds the number of TxOuts %d",
				outStartIndex, outHiddenAutTokenNum, outPublicAutTokenNum, len(msgTx.TxOuts))
		}
		if int(outStartIndex)+int(outHiddenAutTokenNum)+int(outPublicAutTokenNum) > math.MaxUint8 {
			// This is redundant, since a valid Tx will have len(msgTx.TxOuts) < 255
			return nil, fmt.Errorf("outStartIndex (%d) + outHiddenAutTokenNum (%d) + outPublicAutTokenNum (%d) exceeds allowed maximum value %d",
				outStartIndex, outHiddenAutTokenNum, outPublicAutTokenNum, math.MaxUint8)
		}

		if msgTx.HasAutWitness() {
			autWitnessHashComputed := ctautwire.AutWitnessHash(msgTx.AutWitness)
			if !autWitnessHashComputed.IsEqual(&autWitnessHashInScript) {
				return nil, fmt.Errorf("autWitnessHash computed from msgTx.AutWitness (%s) does not match "+
					"autScriptInst.AutWitnessHash (%s)", autWitnessHashComputed, autWitnessHashInScript)
			}
		}
		break

	default:
		return nil, fmt.Errorf("unknown autScript Type %d", autScriptInst.Type())
	}

	// conduct some sanity-checks on autScript 		END

	// populate the generated tokens with host transaction outputs
	extAutScript, err := extscript.NewAndAssembleExtAutScript(autScript, msgTx)
	if err != nil {
		return nil, fmt.Errorf("DetectAndAssembleExtAutScriptFromHostTx: error happens when calling NewExtAutScriptAndAssembleOutputTokens() : %v", err)
	}

	return extAutScript, nil
}

// end of cods
