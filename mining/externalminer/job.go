package externalminer

import (
	"encoding/binary"
	"encoding/hex"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/mining"
	"math/big"
	"strings"
	"time"
)

type SharedBlockTemplate struct {
	BlockTemplate *mining.BlockTemplate
	id            string
	//	cache Hash(Version, PrevBlock, MerkleRoot, Bits, Height), i.e., the parts except the timestamp, as the identifier for block template
}

func NewSharedBlockTemplate(blockTemplate *mining.BlockTemplate) *SharedBlockTemplate {
	return &SharedBlockTemplate{
		BlockTemplate: blockTemplate,
		id:            "",
	}
}

func (sharedTemplate *SharedBlockTemplate) Id() string {
	if strings.Compare(sharedTemplate.id, "") != 0 {
		return sharedTemplate.id
	}

	contentHashExTime := sharedTemplate.BlockTemplate.BlockAbe.Header.ContentHashExcludeTime()
	sharedTemplate.id = hex.EncodeToString(contentHashExTime[:])

	return sharedTemplate.id
}

func (sharedTemplate *SharedBlockTemplate) EraseCachedId() {
	sharedTemplate.id = ""
}

type Job struct {
	SharedBlockTemplate *SharedBlockTemplate
	Epoch               int
	EpochSeed           []byte
	HeaderTimeStamp     time.Time //	As the SharedBlockTemplate may be shared by multiple Jobs and the timeStamp may be modified, Job uses HeaderTimeStamp to store its timeStamp in header.
	ContentHash         chainhash.Hash
	ExtraNonce          uint16
	TargetBoundary      *big.Int
	DistributedTime     time.Time
	id                  string // cache (ContentHash, ExtraNonce) as the identifier for the job
}

func NewJob(sharedTemplate *SharedBlockTemplate, epoch int, epochSeed []byte, headerTimestamp time.Time, contentHash chainhash.Hash, extraNonce uint16, targetBoundary *big.Int, distributedTime time.Time) *Job {
	return &Job{
		SharedBlockTemplate: sharedTemplate,
		Epoch:               epoch,
		EpochSeed:           epochSeed,
		HeaderTimeStamp:     headerTimestamp,
		ContentHash:         contentHash,
		ExtraNonce:          extraNonce,
		TargetBoundary:      targetBoundary,
		DistributedTime:     distributedTime,
		id:                  "",
	}
}

func (job *Job) Id() string {
	if strings.Compare(job.id, "") != 0 {
		return job.id
	}

	idBytes := make([]byte, chainhash.HashSize+2)
	copy(idBytes, job.ContentHash[:])
	binary.LittleEndian.PutUint16(idBytes[chainhash.HashSize:], job.ExtraNonce)

	job.id = hex.EncodeToString(idBytes)

	return job.id
}

type GetWorkReq struct {
	Params *GetWorkReqParams
	Result chan *Job // non-blocking channel
	Err    chan error
}

type GetWorkReqParams struct {
	CurrentJobId string
}

type SubmitWorkReq struct {
	Params *SubmitWorkReqParams
	Err    chan error
}

type SubmitWorkReqParams struct {
	JobId string
	//ContentHash chainhash.Hash
	//ExtraNonce  uint16
	Nonce     uint64
	MixDigest chainhash.Hash //	to prevent DOS attack
}

type SubmitHashRateReq struct {
	Params *SubmitHashRateReqParams
	Err    chan error
}

type SubmitHashRateReqParams struct {
	Id       string
	HashRate float64
}

type WorkerHashRate struct {
	Id         string
	HashRate   float64
	UpdateTime time.Time
}
