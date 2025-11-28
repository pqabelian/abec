package api

import (
	"bytes"
	"fmt"
	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/ctaut/extscript"
	"github.com/abesuite/abec/ctaut/rules"
	"github.com/abesuite/abec/ctaut/script"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
	"math"
)

// Create:
// 1. NewXXXAutScript
// 2. PackageAutScript
// 3. write to TxMemo

// Use:
// 1.

// New Functions	begin
// New Functions	end

// PackageAutScript packages an AutScript to a packagedAutScript, where
// packagedAutScript = commonPrefix (="AUTSCRIPT") || version (in VarInt form) || serializedAutScript (in VarBytes form).
func PackageAutScript(script AutScript) (packagedAutScript []byte, err error) {

	serializedScript, err := script.Serialize()
	if err != nil {
		return nil, err
	}

	length := len([]byte(commonPrefix))
	length += wire.VarIntSerializeSize(uint64(script.Version()))

	length += wire.VarIntSerializeSize(uint64(len(serializedScript))) + len(serializedScript)

	w := bytes.NewBuffer(make([]byte, 0, length))

	_, err = w.Write([]byte(commonPrefix))
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(w, 0, uint64(script.Version()))
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(w, 0, serializedScript)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// UnpackageAutScript unpackages a packagedAutScript to an AutScript, where packagedAutScript is assumed to start from
// commonPrefix (="AUTSCRIPT") || version (in VarInt form) || serializedAutScript (in VarBytes form).
// A packagedAutScript does not satisfy this form will result an error returned.
func UnpackageAutScript(packagedAutScript []byte) (AutScript, error) {
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
		return nil, fmt.Errorf("readed script version (%d) is too large", versionRead)
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

func DetectAndAssembleExtAutScriptFromHostTx(txMsg *wire.MsgTxAbe) (*ExtAutScript, error) {
	if txMsg.Version < wire.TxVersion_Height_464000_Aconcagua {
		return nil, nil
	}
	// detect and extract aut script from TxMemo and check well-formedness
	autScript, err := DetectAndExtractAutScriptFromTxMemo(txMsg.Version, txMsg.TxMemo)
	if err != nil {
		return nil, err
	}
	if autScript == nil {
		return nil, nil
	}

	// populate the generated tokens with host transaction outputs
	extAutScript := extscript.NewExtAutScript(autScript)

	err = extAutScript.AssembleOutputAutTokens(txMsg)
	if err != nil {
		return nil, err
	}
	outputTokens, err := extAutScript.GeneratedTokens()
	if err != nil {
		return nil, err
	}

	switch autScriptInst := autScript.(type) {
	case *RegistrationScript:
		// for inputs, there is no rules

		// for outputs, the claimed issuer tokens must match the generated tokens exactly
		// - all issuer tokens must appear
		// - no unclaimed issuer token appear
		if err = rules.RuleCheckOnIssuerHostClaim(autScriptInst.Issuers(), outputTokens); err != nil {
			return nil, err
		}

	case *ReRegistrationScript:
		// for inputs, note that here is no enough information to
		// 1. check the legality of token
		// 2. check the re-register threshold is meet
		// Above checks have to be delayed until the instance could be seen

		// for outputs, the claimed issuer tokens must match the outputs exactly
		if err = rules.RuleCheckOnIssuerHostClaim(autScriptInst.Issuers(), outputTokens); err != nil {
			return nil, err
		}

	case *MintScript:
		// for inputs, note that here is no enough information to
		// 1. check the legality of token
		// 2. check the mint threshold is meet
		// 3. check the balance proof
		// 4. check whether minted amount conflict with planned total amount
		// Above checks have to be delayed until the instance could be seen

		//witnessHash := chainhash.HashH(tx.AutWitness)
		//if !witnessHash.IsEqual(&script.witnessHash) {
		//	return nil, fmt.Errorf("mismatch witness for script")
		//}

	case *TransferScript:
		// for inputs, note that here is no enough information to
		// 1. check the legality of token
		// 2. check the balance proof
		// Above checks have to be delayed until the instance could be seen

		//witnessHash := chainhash.HashH(tx.AutWitness)
		//if !witnessHash.IsEqual(&script.witnessHash) {
		//	return nil, fmt.Errorf("mismatch witness for script")
		//}

	case *BurnScript:
		// for inputs, note that here is no enough information to
		// 1. check the legality of token
		// 2. check the balance proof
		// Above checks have to be delayed until the instance could be seen

		// for outputs, check the legality of burned token (a.k.a last generated token)
		// In the DetectAndExtractAutScriptFromTxMemo(), SanityCheck has been conducted in Deserialize,
		// in particular, the length of autScriptInst.SerializedAutTxos() is not less than 1.
		serializedAutTxos := autScriptInst.SerializedAutTxos()

		autTxo := &ctautwire.AutTxo{}
		err = autTxo.Deserialize(serializedAutTxos[len(serializedAutTxos)-1])
		if err != nil {
			return nil, err
		}
		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return nil, fmt.Errorf("fail to get last aut txo type from burn script: %v", err)
		}
		// assert the last aut txo must be public
		if autTxoType != abecryptox.AutTxoTypePublic {
			return nil, fmt.Errorf("last aut txo type is not public")
		}

		//witnessHash := chainhash.HashH(tx.AutWitness)
		//if !witnessHash.IsEqual(&script.witnessHash) {
		//	return nil, fmt.Errorf("mismatch witness for script")
		//}
	default:
		return nil, fmt.Errorf("unknown autScript Type %d", autScriptInst.Type())
	}

	return extAutScript, nil
}

// DetectAndExtractAutScriptFromTxMemo
// The difference from DetectAndAssembleExtAutScriptFromHostTx
// ParseAutScript try to deserialize CTAUT script from transaction memo
// todo: This is necessary?
func DetectAndExtractAutScriptFromTxMemo(txVersion uint32, txMemo []byte) (AutScript, error) {
	if txVersion < wire.TxVersion_Height_464000_Aconcagua {
		return nil, nil
	}

	commonPrefixLen := len([]byte(commonPrefix))

	// could not be an AUT transaction
	if len(txMemo) < commonPrefixLen {
		return nil, nil
	}
	if !bytes.Equal(txMemo[:commonPrefixLen], []byte(commonPrefix)) {
		return nil, nil
	}

	// RULE: if commonPrefix appears, the commonPrefix and its following bytes must be a well-formed packagedAutScript,
	// namely, commonPrefix || Version(in VarInt form) || serializedAutScript (in VarBytes form).
	autScript, err := UnpackageAutScript(txMemo)
	if err != nil {
		return nil, err
	}

	// check the script version with the host-txo version
	expectedTxVersion, err := rules.RuleGetTxVersionFromAutScriptVersion(autScript.Version())
	if expectedTxVersion != txVersion {
		return nil, fmt.Errorf("autScript.Version() (%d) corresponds to TxVersion (%d), does not match TxVersion %d",
			autScript.Version(), expectedTxVersion, txVersion)
	}

	return autScript, nil
}
