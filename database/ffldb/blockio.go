// This file contains the implementation functions for reading, writing, and
// otherwise working with the flat files that house the actual blocks.

package ffldb

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/wire"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	// The Bitcoin protocol encodes block height as int32, so max number of
	// blocks is 2^31.  Max block size per the protocol is 32MiB per block.
	// So the theoretical max at the time this comment was written is 64PiB
	// (pebibytes).  With files @ 512MiB each, this would require a maximum
	// of 134,217,728 files.  Thus, choose 9 digits of precision for the
	// filenames.  An additional benefit is 9 digits provides 10^9 files @
	// 512MiB each for a total of ~476.84PiB (roughly 7.4 times the current
	// theoretical max), so there is room for the max block size to grow in
	// the future.
	blockFilenameTemplate   = "%09d.fdb"
	witnessFilenameTemplate = "w%09d.fdb"

	// maxOpenFiles is the max number of open files to maintain in the
	// open blocks cache.  Note that this does not include the current
	// write file, so there will typically be one more than this value open.
	maxOpenFiles = 25

	// maxBlockFileSize is the maximum size for each file used to store
	// blocks.
	//
	// NOTE: The current code uses uint32 for all offsets, so this value
	// must be less than 2^32 (4 GiB).  This is also why it's a typed
	// constant.
	maxBlockFileSize uint32 = 512 * 1024 * 1024 // 512 MiB

	// blockLocSize is the number of bytes the serialized block location
	// data that is stored in the block index.
	//
	// The serialized block location format is:
	//
	//  [0:4]  Block file (4 bytes)
	//  [4:8]  File offset (4 bytes)
	//  [8:12] Block length (4 bytes)
	blockLocSize = 12
)

var (
	// castagnoli houses the Catagnoli polynomial used for CRC-32 checksums.
	castagnoli = crc32.MakeTable(crc32.Castagnoli)
)

// filer is an interface which acts very similar to a *os.File and is typically
// implemented by it.  It exists so the test code can provide mock files for
// properly testing corruption and file system issues.
type filer interface {
	io.Closer
	io.WriterAt
	io.ReaderAt
	Truncate(size int64) error
	Sync() error
}

// lockableFile represents a block file on disk that has been opened for either
// read or read/write access.  It also contains a read-write mutex to support
// multiple concurrent readers.
type lockableFile struct {
	sync.RWMutex
	file filer
}

// writeCursor represents the current file and offset of the block file on disk
// for performing all writes. It also contains a read-write mutex to support
// multiple concurrent readers which can reuse the file handle.
type writeCursor struct {
	sync.RWMutex

	// curFile is the current block file that will be appended to when
	// writing new blocks.
	curFile *lockableFile

	// curFileNum is the current block file number and is used to allow
	// readers to use the same open file handle.
	curFileNum uint32

	// curOffset is the offset in the current write block file where the
	// next new block will be written.
	curOffset uint32
}

// blockStore houses information used to handle reading and writing blocks (and
// part of blocks) into flat files with support for multiple concurrent readers.
type blockStore struct {
	// network is the specific network to use in the flat files for each
	// block.
	network wire.AbelianNet

	// basePath is the base path used for the flat block files and metadata.
	basePath string

	// maxBlockFileSize is the maximum size for each file used to store
	// blocks.  It is defined on the store so the whitebox tests can
	// override the value.
	maxBlockFileSize uint32

	// The following fields are related to the flat files which hold the
	// actual blocks.   The number of open files is limited by maxOpenFiles.
	//
	// obfMutex protects concurrent access to the openBlockFiles map.  It is
	// a RWMutex so multiple readers can simultaneously access open files.
	//
	// openBlockFiles houses the open file handles for existing block files
	// which have been opened read-only along with an individual RWMutex.
	// This scheme allows multiple concurrent readers to the same file while
	// preventing the file from being closed out from under them.
	//
	// lruMutex protects concurrent access to the least recently used list
	// and lookup map.
	//
	// openBlocksLRU tracks how the open files are refenced by pushing the
	// most recently used files to the front of the list thereby trickling
	// the least recently used files to end of the list.  When a file needs
	// to be closed due to exceeding the the max number of allowed open
	// files, the one at the end of the list is closed.
	//
	// fileNumToLRUElem is a mapping between a specific block file number
	// and the associated list element on the least recently used list.
	//
	// Thus, with the combination of these fields, the database supports
	// concurrent non-blocking reads across multiple and individual files
	// along with intelligently limiting the number of open file handles by
	// closing the least recently used files as needed.
	//
	// NOTE: The locking order used throughout is well-defined and MUST be
	// followed.  Failure to do so could lead to deadlocks.  In particular,
	// the locking order is as follows:
	//   1) obfMutex
	//   2) lruMutex
	//   3) writeCursor mutex
	//   4) specific file mutexes
	//
	// None of the mutexes are required to be locked at the same time, and
	// often aren't.  However, if they are to be locked simultaneously, they
	// MUST be locked in the order previously specified.
	//
	// Due to the high performance and multi-read concurrency requirements,
	// write locks should only be held for the minimum time necessary.
	obfMutex         sync.RWMutex
	lruMutex         sync.Mutex
	openBlocksLRU    *list.List // Contains uint32 block file numbers.
	fileNumToLRUElem map[uint32]*list.Element
	openBlockFiles   map[uint32]*lockableFile

	obfWitnessMutex         sync.RWMutex
	lruWitnessMutex         sync.Mutex
	openWitnessLRU          *list.List // Contains uint32 block file numbers.
	fileNumToLRUElemWitness map[uint32]*list.Element
	openWitnessFiles        map[uint32]*lockableFile

	// writeCursor houses the state for the current file and location that
	// new blocks are written to.
	writeCursor           *writeCursor
	writeCursorForWitness *writeCursor

	// These functions are set to openFile, openWriteFile, and deleteFile by
	// default, but are exposed here to allow the whitebox tests to replace
	// them when working with mock files.
	openFileFunc      func(fileNum uint32) (*lockableFile, error)
	openWriteFileFunc func(fileNum uint32) (filer, error)
	deleteFileFunc    func(fileNum uint32) error

	openWitnessFileFunc      func(fileNum uint32) (*lockableFile, error)
	openWriteWitnessFileFunc func(fileNum uint32) (filer, error)
	deleteWitnessFileFunc    func(fileNum uint32) error
}

// blockLocation identifies a particular block file and location.
type blockLocation struct {
	blockFileNum uint32
	fileOffset   uint32
	blockLen     uint32
}

type witnessLocation struct {
	witnessFileNum uint32
	fileOffset     uint32
	witnessLen     uint32
}

// deserializeBlockLoc deserializes the passed serialized block location
// information.  This is data stored into the block index metadata for each
// block.  The serialized data passed to this function MUST be at least
// blockLocSize bytes or it will panic.  The error check is avoided here because
// this information will always be coming from the block index which includes a
// checksum to detect corruption.  Thus it is safe to use this unchecked here.
func deserializeBlockLoc(serializedLoc []byte) blockLocation {
	// The serialized block location format is:
	//
	//  [0:4]  Block file (4 bytes)
	//  [4:8]  File offset (4 bytes)
	//  [8:12] Block length (4 bytes)
	return blockLocation{
		blockFileNum: byteOrder.Uint32(serializedLoc[0:4]),
		fileOffset:   byteOrder.Uint32(serializedLoc[4:8]),
		blockLen:     byteOrder.Uint32(serializedLoc[8:12]),
	}
}

func deserializeWitnessLoc(serializedLoc []byte) witnessLocation {
	// The serialized block location format is:
	//
	//  [0:4]  Block file (4 bytes)
	//  [4:8]  File offset (4 bytes)
	//  [8:12] Block length (4 bytes)
	return witnessLocation{
		witnessFileNum: byteOrder.Uint32(serializedLoc[0:4]),
		fileOffset:     byteOrder.Uint32(serializedLoc[4:8]),
		witnessLen:     byteOrder.Uint32(serializedLoc[8:12]),
	}
}

// serializeBlockLoc returns the serialization of the passed block location.
// This is data to be stored into the block index metadata for each block.
func serializeBlockLoc(loc blockLocation) []byte {
	// The serialized block location format is:
	//
	//  [0:4]  Block file (4 bytes)
	//  [4:8]  File offset (4 bytes)
	//  [8:12] Block length (4 bytes)
	var serializedData [12]byte
	byteOrder.PutUint32(serializedData[0:4], loc.blockFileNum)
	byteOrder.PutUint32(serializedData[4:8], loc.fileOffset)
	byteOrder.PutUint32(serializedData[8:12], loc.blockLen)
	return serializedData[:]
}

func serializeWitnessLoc(loc witnessLocation) []byte {
	// The serialized block location format is:
	//
	//  [0:4]  Block file (4 bytes)
	//  [4:8]  File offset (4 bytes)
	//  [8:12] Block length (4 bytes)
	var serializedData [12]byte
	byteOrder.PutUint32(serializedData[0:4], loc.witnessFileNum)
	byteOrder.PutUint32(serializedData[4:8], loc.fileOffset)
	byteOrder.PutUint32(serializedData[8:12], loc.witnessLen)
	return serializedData[:]
}

// blockFilePath return the file path for the provided block file number.
func blockFilePath(dbPath string, fileNum uint32) string {
	fileName := fmt.Sprintf(blockFilenameTemplate, fileNum)
	return filepath.Join(dbPath, fileName)
}

func witnessFilePath(dbPath string, fileNum uint32) string {
	fileName := fmt.Sprintf(witnessFilenameTemplate, fileNum)
	return filepath.Join(dbPath, fileName)
}

// openWriteFile returns a file handle for the passed flat file number in
// read/write mode.  The file will be created if needed.  It is typically used
// for the current file that will have all new data appended.  Unlike openFile,
// this function does not keep track of the open file and it is not subject to
// the maxOpenFiles limit.
func (s *blockStore) openWriteFile(fileNum uint32) (filer, error) {
	// The current block file needs to be read-write so it is possible to
	// append to it.  Also, it shouldn't be part of the least recently used
	// file.
	filePath := blockFilePath(s.basePath, fileNum)
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		str := fmt.Sprintf("failed to open file %q: %v", filePath, err)
		return nil, makeDbErr(database.ErrDriverSpecific, str, err)
	}

	return file, nil
}

func (s *blockStore) openWriteWitnessFile(fileNum uint32) (filer, error) {
	// The current block file needs to be read-write so it is possible to
	// append to it.  Also, it shouldn't be part of the least recently used
	// file.
	filePath := witnessFilePath(s.basePath, fileNum)
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		str := fmt.Sprintf("failed to open file %q: %v", filePath, err)
		return nil, makeDbErr(database.ErrDriverSpecific, str, err)
	}

	return file, nil
}

// openFile returns a read-only file handle for the passed flat file number.
// The function also keeps track of the open files, performs least recently
// used tracking, and limits the number of open files to maxOpenFiles by closing
// the least recently used file as needed.
//
// This function MUST be called with the overall files mutex (s.obfMutex) locked
// for WRITES.
func (s *blockStore) openFile(fileNum uint32) (*lockableFile, error) {
	// Open the appropriate file as read-only.
	filePath := blockFilePath(s.basePath, fileNum)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, makeDbErr(database.ErrDriverSpecific, err.Error(),
			err)
	}
	blockFile := &lockableFile{file: file}

	// Close the least recently used file if the file exceeds the max
	// allowed open files.  This is not done until after the file open in
	// case the file fails to open, there is no need to close any files.
	//
	// A write lock is required on the LRU list here to protect against
	// modifications happening as already open files are read from and
	// shuffled to the front of the list.
	//
	// Also, add the file that was just opened to the front of the least
	// recently used list to indicate it is the most recently used file and
	// therefore should be closed last.
	s.lruMutex.Lock()
	lruList := s.openBlocksLRU
	if lruList.Len() >= maxOpenFiles {
		lruFileNum := lruList.Remove(lruList.Back()).(uint32)
		oldBlockFile := s.openBlockFiles[lruFileNum]

		// Close the old file under the write lock for the file in case
		// any readers are currently reading from it so it's not closed
		// out from under them.
		oldBlockFile.Lock()
		_ = oldBlockFile.file.Close()
		oldBlockFile.Unlock()

		delete(s.openBlockFiles, lruFileNum)
		delete(s.fileNumToLRUElem, lruFileNum)
	}
	s.fileNumToLRUElem[fileNum] = lruList.PushFront(fileNum)
	s.lruMutex.Unlock()

	// Store a reference to it in the open block files map.
	s.openBlockFiles[fileNum] = blockFile

	return blockFile, nil
}

func (s *blockStore) openWitnessFile(fileNum uint32) (*lockableFile, error) {
	// Open the appropriate file as read-only.
	filePath := witnessFilePath(s.basePath, fileNum)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, makeDbErr(database.ErrDriverSpecific, err.Error(),
			err)
	}
	witnessFile := &lockableFile{file: file}

	// Close the least recently used file if the file exceeds the max
	// allowed open files.  This is not done until after the file open in
	// case the file fails to open, there is no need to close any files.
	//
	// A write lock is required on the LRU list here to protect against
	// modifications happening as already open files are read from and
	// shuffled to the front of the list.
	//
	// Also, add the file that was just opened to the front of the least
	// recently used list to indicate it is the most recently used file and
	// therefore should be closed last.
	s.lruWitnessMutex.Lock()
	lruList := s.openWitnessLRU
	if lruList.Len() >= maxOpenFiles {
		lruFileNum := lruList.Remove(lruList.Back()).(uint32)
		oldWitnessFile := s.openWitnessFiles[lruFileNum]

		// Close the old file under the write lock for the file in case
		// any readers are currently reading from it so it's not closed
		// out from under them.
		oldWitnessFile.Lock()
		_ = oldWitnessFile.file.Close()
		oldWitnessFile.Unlock()

		delete(s.openWitnessFiles, lruFileNum)
		delete(s.fileNumToLRUElemWitness, lruFileNum)
	}
	s.fileNumToLRUElemWitness[fileNum] = lruList.PushFront(fileNum)
	s.lruWitnessMutex.Unlock()

	// Store a reference to it in the open block files map.
	s.openWitnessFiles[fileNum] = witnessFile

	return witnessFile, nil
}

// deleteFile removes the block file for the passed flat file number.  The file
// must already be closed and it is the responsibility of the caller to do any
// other state cleanup necessary.
func (s *blockStore) deleteFile(fileNum uint32) error {
	filePath := blockFilePath(s.basePath, fileNum)
	if err := os.Remove(filePath); err != nil {
		return makeDbErr(database.ErrDriverSpecific, err.Error(), err)
	}

	return nil
}

func (s *blockStore) deleteWitnessFile(fileNum uint32) error {
	filePath := witnessFilePath(s.basePath, fileNum)
	if err := os.Remove(filePath); err != nil {
		return makeDbErr(database.ErrDriverSpecific, err.Error(), err)
	}

	return nil
}

// blockFile attempts to return an existing file handle for the passed flat file
// number if it is already open as well as marking it as most recently used.  It
// will also open the file when it's not already open subject to the rules
// described in openFile.
//
// NOTE: The returned block file will already have the read lock acquired and
// the caller MUST call .RUnlock() to release it once it has finished all read
// operations.  This is necessary because otherwise it would be possible for a
// separate goroutine to close the file after it is returned from here, but
// before the caller has acquired a read lock.
func (s *blockStore) blockFile(fileNum uint32) (*lockableFile, error) {
	// When the requested block file is open for writes, return it.
	wc := s.writeCursor
	wc.RLock()
	if fileNum == wc.curFileNum && wc.curFile.file != nil {
		obf := wc.curFile
		obf.RLock()
		wc.RUnlock()
		return obf, nil
	}
	wc.RUnlock()

	// Try to return an open file under the overall files read lock.
	s.obfMutex.RLock()
	if obf, ok := s.openBlockFiles[fileNum]; ok {
		s.lruMutex.Lock()
		s.openBlocksLRU.MoveToFront(s.fileNumToLRUElem[fileNum])
		s.lruMutex.Unlock()

		obf.RLock()
		s.obfMutex.RUnlock()
		return obf, nil
	}
	s.obfMutex.RUnlock()

	// Since the file isn't open already, need to check the open block files
	// map again under write lock in case multiple readers got here and a
	// separate one is already opening the file.
	s.obfMutex.Lock()
	if obf, ok := s.openBlockFiles[fileNum]; ok {
		obf.RLock()
		s.obfMutex.Unlock()
		return obf, nil
	}

	// The file isn't open, so open it while potentially closing the least
	// recently used one as needed.
	obf, err := s.openFileFunc(fileNum)
	if err != nil {
		s.obfMutex.Unlock()
		return nil, err
	}
	obf.RLock()
	s.obfMutex.Unlock()
	return obf, nil
}

func (s *blockStore) witnessFile(fileNum uint32) (*lockableFile, error) {
	// When the requested block file is open for writes, return it.
	wc := s.writeCursorForWitness
	wc.RLock()
	if fileNum == wc.curFileNum && wc.curFile.file != nil {
		obf := wc.curFile
		obf.RLock()
		wc.RUnlock()
		return obf, nil
	}
	wc.RUnlock()

	// Try to return an open file under the overall files read lock.
	s.obfWitnessMutex.RLock()
	if obf, ok := s.openWitnessFiles[fileNum]; ok {
		s.lruWitnessMutex.Lock()
		s.openWitnessLRU.MoveToFront(s.fileNumToLRUElemWitness[fileNum])
		s.lruWitnessMutex.Unlock()

		obf.RLock()
		s.obfWitnessMutex.RUnlock()
		return obf, nil
	}
	s.obfWitnessMutex.RUnlock()

	// Since the file isn't open already, need to check the open block files
	// map again under write lock in case multiple readers got here and a
	// separate one is already opening the file.
	s.obfWitnessMutex.Lock()
	if obf, ok := s.openWitnessFiles[fileNum]; ok {
		obf.RLock()
		s.obfWitnessMutex.Unlock()
		return obf, nil
	}

	// The file isn't open, so open it while potentially closing the least
	// recently used one as needed.
	obf, err := s.openWitnessFileFunc(fileNum)
	if err != nil {
		s.obfWitnessMutex.Unlock()
		return nil, err
	}
	obf.RLock()
	s.obfWitnessMutex.Unlock()
	return obf, nil
}

// writeData is a helper function for writeBlock which writes the provided data
// at the current write offset and updates the write cursor accordingly.  The
// field name parameter is only used when there is an error to provide a nicer
// error message.
//
// The write cursor will be advanced the number of bytes actually written in the
// event of failure.
//
// NOTE: This function MUST be called with the write cursor current file lock
// held and must only be called during a write transaction so it is effectively
// locked for writes.  Also, the write cursor current file must NOT be nil.
func (s *blockStore) writeData(data []byte, fieldName string) error {
	wc := s.writeCursor
	n, err := wc.curFile.file.WriteAt(data, int64(wc.curOffset))
	wc.curOffset += uint32(n)
	if err != nil {
		str := fmt.Sprintf("failed to write %s to file %d at "+
			"offset %d: %v", fieldName, wc.curFileNum,
			wc.curOffset-uint32(n), err)
		return makeDbErr(database.ErrDriverSpecific, str, err)
	}

	return nil
}

func (s *blockStore) writeDataWitness(data []byte, fieldName string) error {
	wc := s.writeCursorForWitness
	n, err := wc.curFile.file.WriteAt(data, int64(wc.curOffset))
	wc.curOffset += uint32(n)
	if err != nil {
		str := fmt.Sprintf("failed to write %s to file %d at "+
			"offset %d: %v", fieldName, wc.curFileNum,
			wc.curOffset-uint32(n), err)
		return makeDbErr(database.ErrDriverSpecific, str, err)
	}

	return nil
}

// writeBlock appends the specified raw block bytes to the store's write cursor
// location and increments it accordingly.  When the block would exceed the max
// file size for the current flat file, this function will close the current
// file, create the next file, update the write cursor, and write the block to
// the new file.
//
// The write cursor will also be advanced the number of bytes actually written
// in the event of failure.
//
// Format: <network><block length><serialized block><checksum>
func (s *blockStore) writeBlock(rawBlock []byte) (blockLocation, error) {
	// Compute how many bytes will be written.
	// 4 bytes each for block network + 4 bytes for block length +
	// length of raw block + 4 bytes for checksum.
	blockLen := uint32(len(rawBlock))
	fullLen := blockLen + 12

	// Move to the next block file if adding the new block would exceed the
	// max allowed size for the current block file.  Also detect overflow
	// to be paranoid, even though it isn't possible currently, numbers
	// might change in the future to make it possible.
	//
	// NOTE: The writeCursor.offset field isn't protected by the mutex
	// since it's only read/changed during this function which can only be
	// called during a write transaction, of which there can be only one at
	// a time.
	wc := s.writeCursor
	finalOffset := wc.curOffset + fullLen
	if finalOffset < wc.curOffset || finalOffset > s.maxBlockFileSize {
		// This is done under the write cursor lock since the curFileNum
		// field is accessed elsewhere by readers.
		//
		// Close the current write file to force a read-only reopen
		// with LRU tracking.  The close is done under the write lock
		// for the file to prevent it from being closed out from under
		// any readers currently reading from it.
		wc.Lock()
		wc.curFile.Lock()
		if wc.curFile.file != nil {
			_ = wc.curFile.file.Close()
			wc.curFile.file = nil
		}
		wc.curFile.Unlock()

		// Start writes into next file.
		wc.curFileNum++
		wc.curOffset = 0
		wc.Unlock()
	}

	// All writes are done under the write lock for the file to ensure any
	// readers are finished and blocked first.
	wc.curFile.Lock()
	defer wc.curFile.Unlock()

	// Open the current file if needed.  This will typically only be the
	// case when moving to the next file to write to or on initial database
	// load.  However, it might also be the case if rollbacks happened after
	// file writes started during a transaction commit.
	if wc.curFile.file == nil {
		file, err := s.openWriteFileFunc(wc.curFileNum)
		if err != nil {
			return blockLocation{}, err
		}
		wc.curFile.file = file
	}

	// Bitcoin network.
	origOffset := wc.curOffset
	hasher := crc32.New(castagnoli)
	var scratch [4]byte
	byteOrder.PutUint32(scratch[:], uint32(s.network))
	if err := s.writeData(scratch[:], "network"); err != nil {
		return blockLocation{}, err
	}
	_, _ = hasher.Write(scratch[:])

	// Block length.
	byteOrder.PutUint32(scratch[:], blockLen)
	if err := s.writeData(scratch[:], "block length"); err != nil {
		return blockLocation{}, err
	}
	_, _ = hasher.Write(scratch[:])

	// Serialized block.
	if err := s.writeData(rawBlock[:], "block"); err != nil {
		return blockLocation{}, err
	}
	_, _ = hasher.Write(rawBlock)

	// Castagnoli CRC-32 as a checksum of all the previous.
	if err := s.writeData(hasher.Sum(nil), "checksum"); err != nil {
		return blockLocation{}, err
	}

	loc := blockLocation{
		blockFileNum: wc.curFileNum,
		fileOffset:   origOffset,
		blockLen:     fullLen,
	}
	return loc, nil
}

// Format: <network><witness length><witness><checksum>
func (s *blockStore) writeWitness(rawWitness [][]byte) (witnessLocation, error) {
	// Compute how many bytes will be written.
	// 4 bytes each for block network + 4 bytes for block length +
	// length of raw block + 4 bytes for checksum.
	witnessLen := uint32(4)
	for _, witness := range rawWitness {
		witnessLen += 4 + uint32(len(witness))
	}
	fullLen := witnessLen + 12

	// Move to the next block file if adding the new block would exceed the
	// max allowed size for the current block file.  Also detect overflow
	// to be paranoid, even though it isn't possible currently, numbers
	// might change in the future to make it possible.
	//
	// NOTE: The writeCursor.offset field isn't protected by the mutex
	// since it's only read/changed during this function which can only be
	// called during a write transaction, of which there can be only one at
	// a time.
	wc := s.writeCursorForWitness
	finalOffset := wc.curOffset + fullLen
	// TODO change the number of block not the size of file
	if finalOffset < wc.curOffset || finalOffset > s.maxBlockFileSize {
		// This is done under the write cursor lock since the curFileNum
		// field is accessed elsewhere by readers.
		//
		// Close the current write file to force a read-only reopen
		// with LRU tracking.  The close is done under the write lock
		// for the file to prevent it from being closed out from under
		// any readers currently reading from it.
		wc.Lock()
		wc.curFile.Lock()
		if wc.curFile.file != nil {
			_ = wc.curFile.file.Close()
			wc.curFile.file = nil
		}
		wc.curFile.Unlock()

		// Start writes into next file.
		wc.curFileNum++
		wc.curOffset = 0
		wc.Unlock()
	}

	// All writes are done under the write lock for the file to ensure any
	// readers are finished and blocked first.
	wc.curFile.Lock()
	defer wc.curFile.Unlock()

	// Open the current file if needed.  This will typically only be the
	// case when moving to the next file to write to or on initial database
	// load.  However, it might also be the case if rollbacks happened after
	// file writes started during a transaction commit.
	if wc.curFile.file == nil {
		file, err := s.openWriteWitnessFileFunc(wc.curFileNum)
		if err != nil {
			return witnessLocation{}, err
		}
		wc.curFile.file = file
	}

	// Bitcoin network.
	origOffset := wc.curOffset
	hasher := crc32.New(castagnoli)
	var scratch [4]byte
	byteOrder.PutUint32(scratch[:], uint32(s.network))
	if err := s.writeDataWitness(scratch[:], "network"); err != nil {
		return witnessLocation{}, err
	}
	_, _ = hasher.Write(scratch[:])

	// witness length.
	byteOrder.PutUint32(scratch[:], witnessLen)
	if err := s.writeDataWitness(scratch[:], "block length"); err != nil {
		return witnessLocation{}, err
	}
	_, _ = hasher.Write(scratch[:])

	// witness num
	byteOrder.PutUint32(scratch[:], uint32(len(rawWitness)))
	if err := s.writeDataWitness(scratch[:], "block length"); err != nil {
		return witnessLocation{}, err
	}
	_, _ = hasher.Write(scratch[:])

	// Witness [txHash, witness]
	for i := 0; i < len(rawWitness); i++ {
		// length
		byteOrder.PutUint32(scratch[:], uint32(len(rawWitness[i])))
		if err := s.writeDataWitness(scratch[:], "block length"); err != nil {
			return witnessLocation{}, err
		}
		_, _ = hasher.Write(scratch[:])
		// witness data
		if err := s.writeDataWitness(rawWitness[i], "witness"); err != nil {
			return witnessLocation{}, err
		}
		_, _ = hasher.Write(rawWitness[i])
	}

	// Castagnoli CRC-32 as a checksum of all the previous.
	if err := s.writeDataWitness(hasher.Sum(nil), "checksum"); err != nil {
		return witnessLocation{}, err
	}

	loc := witnessLocation{
		witnessFileNum: wc.curFileNum,
		fileOffset:     origOffset,
		witnessLen:     fullLen,
	}
	return loc, nil
}

// readBlock reads the specified block record and returns the serialized block.
// It ensures the integrity of the block data by checking that the serialized
// network matches the current network associated with the block store and
// comparing the calculated checksum against the one stored in the flat file.
// This function also automatically handles all file management such as opening
// and closing files as necessary to stay within the maximum allowed open files
// limit.
//
// Returns ErrDriverSpecific if the data fails to read for any reason and
// ErrCorruption if the checksum of the read data doesn't match the checksum
// read from the file.
//
// Format: <network><block length><serialized block><checksum>
func (s *blockStore) readBlock(hash *chainhash.Hash, loc blockLocation) ([]byte, error) {
	// Get the referenced block file handle opening the file as needed.  The
	// function also handles closing files as needed to avoid going over the
	// max allowed open files.
	blockFile, err := s.blockFile(loc.blockFileNum)
	if err != nil {
		return nil, err
	}

	serializedData := make([]byte, loc.blockLen)
	n, err := blockFile.file.ReadAt(serializedData, int64(loc.fileOffset))
	blockFile.RUnlock()
	if err != nil {
		str := fmt.Sprintf("failed to read block %s from file %d, "+
			"offset %d: %v", hash, loc.blockFileNum, loc.fileOffset,
			err)
		return nil, makeDbErr(database.ErrDriverSpecific, str, err)
	}

	// Calculate the checksum of the read data and ensure it matches the
	// serialized checksum.  This will detect any data corruption in the
	// flat file without having to do much more expensive merkle root
	// calculations on the loaded block.
	serializedChecksum := binary.BigEndian.Uint32(serializedData[n-4:])
	calculatedChecksum := crc32.Checksum(serializedData[:n-4], castagnoli)
	if serializedChecksum != calculatedChecksum {
		str := fmt.Sprintf("block data for block %s checksum "+
			"does not match - got %x, want %x", hash,
			calculatedChecksum, serializedChecksum)
		return nil, makeDbErr(database.ErrCorruption, str, nil)
	}

	// The network associated with the block must match the current active
	// network, otherwise somebody probably put the block files for the
	// wrong network in the directory.
	serializedNet := byteOrder.Uint32(serializedData[:4])
	if serializedNet != uint32(s.network) {
		str := fmt.Sprintf("block data for block %s is for the "+
			"wrong network - got %d, want %d", hash, serializedNet,
			uint32(s.network))
		return nil, makeDbErr(database.ErrDriverSpecific, str, nil)
	}

	// The raw block excludes the network, length of the block, and
	// checksum.
	return serializedData[8 : n-4], nil
}

func (s *blockStore) readWitness(hash *chainhash.Hash, loc witnessLocation) ([][]byte, error) {
	// Get the referenced block file handle opening the file as needed.  The
	// function also handles closing files as needed to avoid going over the
	// max allowed open files.
	witnessFile, err := s.witnessFile(loc.witnessFileNum)
	if err != nil {
		return nil, err
	}

	serializedData := make([]byte, loc.witnessLen)
	n, err := witnessFile.file.ReadAt(serializedData, int64(loc.fileOffset))
	witnessFile.RUnlock()
	if err != nil {
		str := fmt.Sprintf("failed to read block %s from file %d, "+
			"offset %d: %v", hash, loc.witnessFileNum, loc.fileOffset,
			err)
		return nil, makeDbErr(database.ErrDriverSpecific, str, err)
	}

	// Calculate the checksum of the read data and ensure it matches the
	// serialized checksum.  This will detect any data corruption in the
	// flat file without having to do much more expensive merkle root
	// calculations on the loaded block.
	serializedChecksum := binary.BigEndian.Uint32(serializedData[n-4:])
	calculatedChecksum := crc32.Checksum(serializedData[:n-4], castagnoli)
	if serializedChecksum != calculatedChecksum {
		str := fmt.Sprintf("block data for block %s checksum "+
			"does not match - got %x, want %x", hash,
			calculatedChecksum, serializedChecksum)
		return nil, makeDbErr(database.ErrCorruption, str, nil)
	}

	// The network associated with the block must match the current active
	// network, otherwise somebody probably put the block files for the
	// wrong network in the directory.
	serializedNet := byteOrder.Uint32(serializedData[:4])
	if serializedNet != uint32(s.network) {
		str := fmt.Sprintf("witness data for witness %s is for the "+
			"wrong network - got %d, want %d", hash, serializedNet,
			uint32(s.network))
		return nil, makeDbErr(database.ErrDriverSpecific, str, nil)
	}

	witnessesLength := byteOrder.Uint32(serializedData[4:8])
	if uint32(len(serializedData)) != 12+witnessesLength {
		str := fmt.Sprintf("witness data for witness %s is for the "+
			"wrong witness - got %d, want %d", hash, witnessesLength,
			12+witnessesLength)
		return nil, makeDbErr(database.ErrDriverSpecific, str, nil)
	}

	// The raw block excludes the network, length of the block, and
	// checksum.
	witnessNum := byteOrder.Uint32(serializedData[8:12])
	rawWitness := make([][]byte, witnessNum)
	cur, end := uint32(12), uint32(n-4)
	for i := uint32(0); i < witnessNum; i++ {
		witnessLen := byteOrder.Uint32(serializedData[cur : cur+4])
		rawWitness[i] = make([]byte, witnessLen)
		copy(rawWitness[i][:], serializedData[cur+4:cur+4+witnessLen])
		cur = cur + 4 + witnessLen
	}
	if cur != end {
		str := fmt.Sprintf("witness data for witness %s is for "+
			"wrong length", hash)
		return nil, makeDbErr(database.ErrDriverSpecific, str, nil)
	}
	return rawWitness, nil
}

// readBlockRegion reads the specified amount of data at the provided offset for
// a given block location.  The offset is relative to the start of the
// serialized block (as opposed to the beginning of the block record).  This
// function automatically handles all file management such as opening and
// closing files as necessary to stay within the maximum allowed open files
// limit.
//
// Returns ErrDriverSpecific if the data fails to read for any reason.
func (s *blockStore) readBlockRegion(loc blockLocation, offset, numBytes uint32) ([]byte, error) {
	// Get the referenced block file handle opening the file as needed.  The
	// function also handles closing files as needed to avoid going over the
	// max allowed open files.
	blockFile, err := s.blockFile(loc.blockFileNum)
	if err != nil {
		return nil, err
	}

	// Regions are offsets into the actual block, however the serialized
	// data for a block includes an initial 4 bytes for network + 4 bytes
	// for block length.  Thus, add 8 bytes to adjust.
	readOffset := loc.fileOffset + 8 + offset
	serializedData := make([]byte, numBytes)
	_, err = blockFile.file.ReadAt(serializedData, int64(readOffset))
	blockFile.RUnlock()
	if err != nil {
		str := fmt.Sprintf("failed to read region from block file %d, "+
			"offset %d, len %d: %v", loc.blockFileNum, readOffset,
			numBytes, err)
		return nil, makeDbErr(database.ErrDriverSpecific, str, err)
	}

	return serializedData, nil
}

func (s *blockStore) readWitnessRegion(loc witnessLocation, offset, numBytes uint32) ([]byte, error) {
	// Get the referenced block file handle opening the file as needed.  The
	// function also handles closing files as needed to avoid going over the
	// max allowed open files.
	witnessFile, err := s.witnessFile(loc.witnessFileNum)
	if err != nil {
		return nil, err
	}

	// Regions are offsets into the actual block, however the serialized
	// data for a block includes an initial 4 bytes for network + 4 bytes
	// for block length.  Thus, add 8 bytes to adjust.
	readOffset := loc.fileOffset + 8 + offset
	serializedData := make([]byte, numBytes)
	_, err = witnessFile.file.ReadAt(serializedData, int64(readOffset))
	witnessFile.RUnlock()
	if err != nil {
		str := fmt.Sprintf("failed to read region from block file %d, "+
			"offset %d, len %d: %v", loc.witnessFileNum, readOffset,
			numBytes, err)
		return nil, makeDbErr(database.ErrDriverSpecific, str, err)
	}

	return serializedData, nil
}

// syncBlocks performs a file system sync on the flat file associated with the
// store's current write cursor.  It is safe to call even when there is not a
// current write file in which case it will have no effect.
//
// This is used when flushing cached metadata updates to disk to ensure all the
// block data is fully written before updating the metadata.  This ensures the
// metadata and block data can be properly reconciled in failure scenarios.
func (s *blockStore) syncBlocks() error {
	wc := s.writeCursor
	wc.RLock()
	defer wc.RUnlock()

	// Nothing to do if there is no current file associated with the write
	// cursor.
	wc.curFile.RLock()
	defer wc.curFile.RUnlock()
	if wc.curFile.file == nil {
		return nil
	}

	// Sync the file to disk.
	if err := wc.curFile.file.Sync(); err != nil {
		str := fmt.Sprintf("failed to sync file %d: %v", wc.curFileNum,
			err)
		return makeDbErr(database.ErrDriverSpecific, str, err)
	}

	return nil
}

func (s *blockStore) syncWitness() error {
	wc := s.writeCursorForWitness
	wc.RLock()
	defer wc.RUnlock()

	// Nothing to do if there is no current file associated with the write
	// cursor.
	wc.curFile.RLock()
	defer wc.curFile.RUnlock()
	if wc.curFile.file == nil {
		return nil
	}

	// Sync the file to disk.
	if err := wc.curFile.file.Sync(); err != nil {
		str := fmt.Sprintf("failed to sync file %d: %v", wc.curFileNum,
			err)
		return makeDbErr(database.ErrDriverSpecific, str, err)
	}

	return nil
}

// handleRollback rolls the block files on disk back to the provided file number
// and offset.  This involves potentially deleting and truncating the files that
// were partially written.
//
// There are effectively two scenarios to consider here:
//   1) Transient write failures from which recovery is possible
//   2) More permanent failures such as hard disk death and/or removal
//
// In either case, the write cursor will be repositioned to the old block file
// offset regardless of any other errors that occur while attempting to undo
// writes.
//
// For the first scenario, this will lead to any data which failed to be undone
// being overwritten and thus behaves as desired as the system continues to run.
//
// For the second scenario, the metadata which stores the current write cursor
// position within the block files will not have been updated yet and thus if
// the system eventually recovers (perhaps the hard drive is reconnected), it
// will also lead to any data which failed to be undone being overwritten and
// thus behaves as desired.
//
// Therefore, any errors are simply logged at a warning level rather than being
// returned since there is nothing more that could be done about it anyways.
func (s *blockStore) handleRollback(oldBlockFileNum, oldBlockOffset uint32) {
	// Grab the write cursor mutex since it is modified throughout this
	// function.
	wc := s.writeCursor
	wc.Lock()
	defer wc.Unlock()

	// Nothing to do if the rollback point is the same as the current write
	// cursor.
	if wc.curFileNum == oldBlockFileNum && wc.curOffset == oldBlockOffset {
		return
	}

	// Regardless of any failures that happen below, reposition the write
	// cursor to the old block file and offset.
	defer func() {
		wc.curFileNum = oldBlockFileNum
		wc.curOffset = oldBlockOffset
	}()

	log.Debugf("ROLLBACK: Rolling back to file %d, offset %d",
		oldBlockFileNum, oldBlockOffset)

	// Close the current write file if it needs to be deleted.  Then delete
	// all files that are newer than the provided rollback file while
	// also moving the write cursor file backwards accordingly.
	if wc.curFileNum > oldBlockFileNum {
		wc.curFile.Lock()
		if wc.curFile.file != nil {
			_ = wc.curFile.file.Close()
			wc.curFile.file = nil
		}
		wc.curFile.Unlock()
	}
	for ; wc.curFileNum > oldBlockFileNum; wc.curFileNum-- {
		if err := s.deleteFileFunc(wc.curFileNum); err != nil {
			log.Warnf("ROLLBACK: Failed to delete block file "+
				"number %d: %v", wc.curFileNum, err)
			return
		}
	}

	// Open the file for the current write cursor if needed.
	wc.curFile.Lock()
	if wc.curFile.file == nil {
		obf, err := s.openWriteFileFunc(wc.curFileNum)
		if err != nil {
			wc.curFile.Unlock()
			log.Warnf("ROLLBACK: %v", err)
			return
		}
		wc.curFile.file = obf
	}

	// Truncate the to the provided rollback offset.
	if err := wc.curFile.file.Truncate(int64(oldBlockOffset)); err != nil {
		wc.curFile.Unlock()
		log.Warnf("ROLLBACK: Failed to truncate file %d: %v",
			wc.curFileNum, err)
		return
	}

	// Sync the file to disk.
	err := wc.curFile.file.Sync()
	wc.curFile.Unlock()
	if err != nil {
		log.Warnf("ROLLBACK: Failed to sync file %d: %v",
			wc.curFileNum, err)
		return
	}
}

func (s *blockStore) handleRollbackForWitness(oldWitnessFileNum, oldWitnessOffset uint32) {
	// Grab the write cursor mutex since it is modified throughout this
	// function.
	wc := s.writeCursorForWitness
	wc.Lock()
	defer wc.Unlock()

	// Nothing to do if the rollback point is the same as the current write
	// cursor.
	if wc.curFileNum == oldWitnessFileNum && wc.curOffset == oldWitnessOffset {
		return
	}

	// Regardless of any failures that happen below, reposition the write
	// cursor to the old block file and offset.
	defer func() {
		wc.curFileNum = oldWitnessFileNum
		wc.curOffset = oldWitnessOffset
	}()

	log.Debugf("ROLLBACK: Rolling back to file %d, offset %d",
		oldWitnessFileNum, oldWitnessOffset)

	// Close the current write file if it needs to be deleted.  Then delete
	// all files that are newer than the provided rollback file while
	// also moving the write cursor file backwards accordingly.
	if wc.curFileNum > oldWitnessFileNum {
		wc.curFile.Lock()
		if wc.curFile.file != nil {
			_ = wc.curFile.file.Close()
			wc.curFile.file = nil
		}
		wc.curFile.Unlock()
	}
	for ; wc.curFileNum > oldWitnessFileNum; wc.curFileNum-- {
		if err := s.deleteWitnessFileFunc(wc.curFileNum); err != nil {
			log.Warnf("ROLLBACK: Failed to delete block file "+
				"number %d: %v", wc.curFileNum, err)
			return
		}
	}

	// Open the file for the current write cursor if needed.
	wc.curFile.Lock()
	if wc.curFile.file == nil {
		obf, err := s.openWriteWitnessFileFunc(wc.curFileNum)
		if err != nil {
			wc.curFile.Unlock()
			log.Warnf("ROLLBACK: %v", err)
			return
		}
		wc.curFile.file = obf
	}

	// Truncate the to the provided rollback offset.
	if err := wc.curFile.file.Truncate(int64(oldWitnessOffset)); err != nil {
		wc.curFile.Unlock()
		log.Warnf("ROLLBACK: Failed to truncate file %d: %v",
			wc.curFileNum, err)
		return
	}

	// Sync the file to disk.
	err := wc.curFile.file.Sync()
	wc.curFile.Unlock()
	if err != nil {
		log.Warnf("ROLLBACK: Failed to sync file %d: %v",
			wc.curFileNum, err)
		return
	}
}

// scanBlockFiles searches the database directory for all flat block files to
// find the end of the most recent file.  This position is considered the
// current write cursor which is also stored in the metadata.  Thus, it is used
// to detect unexpected shutdowns in the middle of writes so the block files
// can be reconciled.
func scanBlockFiles(dbPath string) (int, uint32) {
	lastFile := -1
	fileLen := uint32(0)
	for i := 0; ; i++ {
		filePath := blockFilePath(dbPath, uint32(i))
		st, err := os.Stat(filePath)
		if err != nil {
			break
		}
		lastFile = i

		fileLen = uint32(st.Size())
	}

	log.Tracef("Scan found latest block file #%d with length %d", lastFile,
		fileLen)
	return lastFile, fileLen
}

func scanWitnessFiles(dbPath string, startIdx int) (int, uint32) {
	lastFile := -1
	fileLen := uint32(0)

	log.Tracef("Scan from witness file #%d", startIdx)
	for i := startIdx; ; i++ {
		filePath := witnessFilePath(dbPath, uint32(i))
		st, err := os.Stat(filePath)
		if err != nil {
			break
		}
		lastFile = i

		fileLen = uint32(st.Size())
	}

	log.Tracef("Scan found latest block file #%d with length %d", lastFile,
		fileLen)
	return lastFile, fileLen
}

// newBlockStore returns a new block store with the current block file number
// and offset set and all fields initialized.
func newBlockStore(basePath string, network wire.AbelianNet) *blockStore {
	// Look for the end of the latest block to file to determine what the
	// write cursor position is from the viewpoing of the block files on
	// disk.
	fileNum, fileOff := scanBlockFiles(basePath)
	if fileNum == -1 {
		fileNum = 0
		fileOff = 0
	}

	store := &blockStore{
		network:          network,
		basePath:         basePath,
		maxBlockFileSize: maxBlockFileSize,
		openBlockFiles:   make(map[uint32]*lockableFile),
		openBlocksLRU:    list.New(),
		fileNumToLRUElem: make(map[uint32]*list.Element),

		openWitnessFiles:        make(map[uint32]*lockableFile),
		openWitnessLRU:          list.New(),
		fileNumToLRUElemWitness: make(map[uint32]*list.Element),

		writeCursor: &writeCursor{
			curFile:    &lockableFile{},
			curFileNum: uint32(fileNum),
			curOffset:  fileOff,
		},
	}
	store.openFileFunc = store.openFile
	store.openWriteFileFunc = store.openWriteFile
	store.deleteFileFunc = store.deleteFile

	store.openWitnessFileFunc = store.openWitnessFile
	store.openWriteWitnessFileFunc = store.openWriteWitnessFile
	store.deleteWitnessFileFunc = store.deleteWitnessFile
	return store
}

func fetchMinWitnessFileNum(pdb *db) (int, error) {
	hasMinWitnessFileNum := true
	var minWitnessFileNum []byte
	err := pdb.View(func(tx database.Tx) error {
		minWitnessFileNum = tx.Metadata().Get(minWitnessFileNumKeyName)
		if minWitnessFileNum == nil {
			hasMinWitnessFileNum = false
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	if !hasMinWitnessFileNum {
		log.Infof("Creating min witness file num key...")
		err := addMinWitnessFileNumKey(pdb.cache.ldb)
		return 0, err
	}

	return int(deserializeUint32(minWitnessFileNum)), nil
}

func initWitnessCursor(basePath string, pdb *db) error {
	minIdx, err := fetchMinWitnessFileNum(pdb)
	if err != nil {
		return err
	}

	witnessFileNum, witnessFileOff := scanWitnessFiles(basePath, minIdx)
	if witnessFileNum == -1 {
		witnessFileNum = 0
		witnessFileOff = 0
	}

	pdb.store.writeCursorForWitness = &writeCursor{
		curFile:    &lockableFile{},
		curFileNum: uint32(witnessFileNum),
		curOffset:  witnessFileOff,
	}
	return nil
}
