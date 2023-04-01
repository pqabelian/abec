package ffldb

import (
	"fmt"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/wire"
	"hash/crc32"
)

// The serialized write cursor location format is:
//
//  [0:4]  Block file (4 bytes)
//  [4:8]  File offset (4 bytes)
//  [8:12] Castagnoli CRC-32 checksum (4 bytes)

// serializeWriteRow serialize the current block file and offset where new
// will be written into a format suitable for storage into the metadata.
func serializeWriteRow(curBlockFileNum, curFileOffset uint32) []byte {
	var serializedRow [12]byte
	byteOrder.PutUint32(serializedRow[0:4], curBlockFileNum)
	byteOrder.PutUint32(serializedRow[4:8], curFileOffset)
	checksum := crc32.Checksum(serializedRow[:8], castagnoli)
	byteOrder.PutUint32(serializedRow[8:12], checksum)
	return serializedRow[:]
}

// deserializeWriteRow deserializes the write cursor location stored in the
// metadata.  Returns ErrCorruption if the checksum of the entry doesn't match.
func deserializeWriteRow(writeRow []byte) (uint32, uint32, error) {
	// Ensure the checksum matches.  The checksum is at the end.
	gotChecksum := crc32.Checksum(writeRow[:8], castagnoli)
	wantChecksumBytes := writeRow[8:12]
	wantChecksum := byteOrder.Uint32(wantChecksumBytes)
	if gotChecksum != wantChecksum {
		str := fmt.Sprintf("metadata for write cursor does not match "+
			"the expected checksum - got %d, want %d", gotChecksum,
			wantChecksum)
		return 0, 0, makeDbErr(database.ErrCorruption, str, nil)
	}

	fileNum := byteOrder.Uint32(writeRow[0:4])
	fileOffset := byteOrder.Uint32(writeRow[4:8])
	return fileNum, fileOffset, nil
}

// serializeUint32 serialize the uint32 value.
func serializeUint32(num uint32) []byte {
	var serializedRow [4]byte
	byteOrder.PutUint32(serializedRow[0:4], num)
	return serializedRow[:]
}

// deserializeUint32 deserializes the uint32 value.
func deserializeUint32(num []byte) uint32 {
	res := byteOrder.Uint32(num[0:4])
	return res
}

// reconcileDB reconciles the metadata with the flat block files on disk.  It
// will also initialize the underlying database if the create flag is set.
// todo (prune): depend on the node type
func reconcileDB(pdb *db, nodeType wire.NodeType, trustLevel wire.TrustLevel, create bool) (database.DB, error) {
	// Perform initial internal bucket and value creation during database
	// creation.
	if create {
		if err := initDB(pdb.cache.ldb, nodeType, trustLevel); err != nil {
			return nil, err
		}
	}

	// Compatible with old version of abec.
	hasNodeType, err := nodeTypeExist(pdb)
	if err != nil {
		return nil, err
	}
	if !hasNodeType {
		log.Info("Adding node type in database...")
		err := addNodeTypeKey(pdb.cache.ldb, wire.FullNode)
		if err != nil {
			return nil, err
		}
	}
	hasTrustLevel, err := trustLevelExist(pdb)
	if err != nil {
		return nil, err
	}
	if !hasTrustLevel {
		log.Info("Adding trust level in database...")
		err := addTrustLevelKey(pdb.cache.ldb, wire.TrustLevelMedium)
		if err != nil {
			return nil, err
		}
	}

	// Load the current write cursor position from the metadata.
	var curFileNum, curOffset uint32
	var curWitnessFileNum, curWitnessOffset uint32
	err = pdb.View(func(tx database.Tx) error {
		// For block
		writeRow := tx.Metadata().Get(writeLocKeyName)
		if writeRow == nil {
			str := "write cursor does not exist"
			return makeDbErr(database.ErrCorruption, str, nil)
		}

		var err error
		curFileNum, curOffset, err = deserializeWriteRow(writeRow)

		// For witness
		writeRowForWitness := tx.Metadata().Get(writeLocWitnessKeyName)
		if writeRowForWitness == nil {
			str := "write cursor does not exist"
			return makeDbErr(database.ErrCorruption, str, nil)
		}

		curWitnessFileNum, curWitnessOffset, err = deserializeWriteRow(writeRowForWitness)
		return err
	})
	if err != nil {
		return nil, err
	}

	// When the write cursor position found by scanning the block files on
	// disk is AFTER the position the metadata believes to be true, truncate
	// the files on disk to match the metadata.  This can be a fairly common
	// occurrence in unclean shutdown scenarios while the block files are in
	// the middle of being written.  Since the metadata isn't updated until
	// after the block data is written, this is effectively just a rollback
	// to the known good point before the unclean shutdown.
	wc := pdb.store.writeCursor
	if wc.curFileNum > curFileNum || (wc.curFileNum == curFileNum &&
		wc.curOffset > curOffset) {

		log.Info("Detected unclean shutdown - Repairing...")
		log.Debugf("Metadata claims file %d, offset %d. Block data is "+
			"at file %d, offset %d", curFileNum, curOffset,
			wc.curFileNum, wc.curOffset)
		pdb.store.handleRollback(curFileNum, curOffset)
		log.Infof("Database sync complete")
	}

	wcForWitness := pdb.store.writeCursorForWitness
	if wcForWitness.curFileNum > curWitnessFileNum || (wcForWitness.curFileNum == curWitnessFileNum &&
		wcForWitness.curOffset > curWitnessOffset) {

		log.Info("Detected unclean shutdown - Repairing...")
		log.Debugf("Metadata claims file %d, offset %d. Block data is "+
			"at file %d, offset %d", curWitnessFileNum, curWitnessOffset,
			wcForWitness.curFileNum, wcForWitness.curOffset)
		pdb.store.handleRollbackForWitness(curWitnessFileNum, curWitnessOffset)
		log.Infof("Database sync complete")
	}

	// When the write cursor position found by scanning the block files on
	// disk is BEFORE the position the metadata believes to be true, return
	// a corruption error.  Since sync is called after each block is written
	// and before the metadata is updated, this should only happen in the
	// case of missing, deleted, or truncated block files, which generally
	// is not an easily recoverable scenario.  In the future, it might be
	// possible to rescan and rebuild the metadata from the block files,
	// however, that would need to happen with coordination from a higher
	// layer since it could invalidate other metadata.
	if wc.curFileNum < curFileNum || (wc.curFileNum == curFileNum &&
		wc.curOffset < curOffset) {

		str := fmt.Sprintf("metadata claims file %d, offset %d, but "+
			"block data is at file %d, offset %d", curFileNum,
			curOffset, wc.curFileNum, wc.curOffset)
		log.Warnf("***Database corruption detected***: %v", str)
		return nil, makeDbErr(database.ErrCorruption, str, nil)
	}

	if wcForWitness.curFileNum < curWitnessFileNum || (wcForWitness.curFileNum == curWitnessFileNum &&
		wcForWitness.curOffset < curWitnessOffset) {

		str := fmt.Sprintf("metadata claims file %d, offset %d, but "+
			"block data is at file %d, offset %d", curFileNum,
			curOffset, wcForWitness.curFileNum, wcForWitness.curOffset)
		log.Warnf("***Database corruption detected***: %v", str)
		return nil, makeDbErr(database.ErrCorruption, str, nil)
	}

	return pdb, nil
}
