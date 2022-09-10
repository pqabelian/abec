package externalminer

import (
	"bytes"
	"errors"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/consensus/ethash"
	"github.com/abesuite/abec/mining"
	"strings"
	"sync"
	"time"
)

const (
	hpsUpdateSecs    = 10
	hpsValidSecs     = 120
	hpsDisplayPeriod = 12  //	display hash rate every 12 updates
	jobValiditySecs  = 180 // a job will be deleted from the active job list, since that mean the worker did not request new job in the past 180 seconds.
)

// Config is a descriptor containing the cpu miner configuration.
type Config struct {
	// ChainParams identifies which chain parameters the cpu miner is
	// associated with.
	ChainParams *chaincfg.Params

	//	Ethash manages the cache and dataset for EthashPoW mining.
	Ethash *ethash.Ethash

	// BlockTemplateGenerator identifies the instance to use in order to
	// generate block templates that the miner will attempt to solve.
	BlockTemplateGenerator *mining.BlkTmplGenerator

	// MiningAddr is a master addresses to use for the generated blocks.
	// Each generated block will use derived address from the master address.
	MiningAddr      abeutil.MasterAddress
	MiningAddrBytes []byte

	// HashRateWatermark defines the watermark, and when the hashrate of CPU mining is lower than this watermark, a warning will be triggered.
	// HashRateWatermark int

	// ProcessBlock defines the function to call with any solved blocks.
	// It typically must run the provided block through the same set of
	// rules and handling as any other block coming from the network.
	ProcessBlock func(*abeutil.BlockAbe, blockchain.BehaviorFlags) (bool, error)

	// ConnectedCount defines the function to use to obtain how many other
	// peers the server is connected to.  This is used by the automatic
	// persistent mining routine to determine whether or it should attempt
	// mining.  This is useful because there is no point in mining when not
	// connected to any peers since there would no be anyone to send any
	// found blocks to.
	ConnectedCount func() int32

	// IsCurrent defines the function to use to obtain whether or not the
	// block chain is current.  This is used by the automatic persistent
	// mining routine to determine whether or it should attempt mining.
	// This is useful because there is no point in mining if the chain is
	// not current since any solved blocks would be on a side chain and and
	// up orphaned anyways.
	IsCurrent func() bool
}

// CPUMiner provides facilities for solving blocks (mining) using the CPU in
// a concurrency-safe manner.  It consists of two main goroutines -- a speed
// monitor and a controller for worker goroutines which generate and solve
// blocks.  The number of goroutines can be set via the SetMaxGoRoutines
// function, but the default is based on the number of processor cores in the
// system which is typically sufficient.
type ExternalMiner struct {
	sync.Mutex
	g                *mining.BlkTmplGenerator
	cfg              Config
	ethash           *ethash.Ethash
	started          bool
	submitBlockLock  sync.Mutex
	wg               sync.WaitGroup
	speedMonitorQuit chan struct{}
	quit             chan struct{}

	//	todo: getwork
	latestBlockTemplate     *SharedBlockTemplate
	latestContentHash       chainhash.Hash                  //	used to track the latestBlockTemplate's contentHash
	latestExtraNonce        uint16                          //	used to track the latestExtraNonce for the jobs that are sharing the latestContentHash
	activeBlockTemplates    map[string]*SharedBlockTemplate //	shardBlockTemplateId as the key
	activeJobs              map[string]*Job                 // jobId as the key
	activeBlockTemplateJobs map[string]map[string]struct{}  // sharedBlockTemplateId --> jobIds
	workerHashRates         map[string]*WorkerHashRate

	getWorkCh        chan *GetWorkReq
	submitWorkCh     chan *submitWorkReq
	submitHashRateCh chan *submitHashRateReq

	queryHashRate chan float64
}

// speedMonitor handles tracking the number of hashes per second the mining
// process is performing.  It must be run as a goroutine.
func (m *ExternalMiner) speedMonitor() {
	log.Tracef("External miner speed monitor started")

	hashRate := float64(0)
	hpsDisplayCtr := 0
	ticker := time.NewTicker(time.Second * hpsUpdateSecs)
	defer ticker.Stop()

out:
	for {
		select {
		// Periodic updates from the workers with how many hashes they
		// have performed.
		case submitHashRateReq := <-m.submitHashRateCh:
			workerHashRate, ok := m.workerHashRates[submitHashRateReq.params.MinerId]
			if !ok {
				newWorkerHashRate := &WorkerHashRate{
					MinerId:    submitHashRateReq.params.MinerId,
					HashRate:   submitHashRateReq.params.HashRate,
					UpdateTime: time.Now(),
				}
				m.workerHashRates[newWorkerHashRate.MinerId] = newWorkerHashRate
			} else {
				workerHashRate.HashRate = (workerHashRate.HashRate + submitHashRateReq.params.HashRate) / 2
				workerHashRate.UpdateTime = time.Now()
			}

		// Time to update the hash rate of the external miner, which is actually contributed by the workers
		case <-ticker.C:
			toDelWorkerId := make([]string, 0, len(m.workerHashRates))
			hashRate = float64(0)
			for workerId, workerHashRate := range m.workerHashRates {

				if time.Since(workerHashRate.UpdateTime).Seconds() > hpsValidSecs {
					//	the worker has not update its hash rate for more than hpsValidSecs seconds
					toDelWorkerId = append(toDelWorkerId, workerId)
				} else {
					hashRate += workerHashRate.HashRate
				}
			}

			for i := 0; i < len(toDelWorkerId); i++ {
				delete(m.workerHashRates, toDelWorkerId[i])
			}

			hpsDisplayCtr++
			if hpsDisplayCtr == hpsDisplayPeriod {
				//	2 minutes based on (ticker, hpsUpdateSecs)
				log.Infof("Hash speed: %6.0f kilohashes/s",
					hashRate/1000)

				hpsDisplayCtr = 0
			}

		// Request for the number of hashes per second.
		case m.queryHashRate <- hashRate:
			// Nothing to do.

		case <-m.speedMonitorQuit:
			break out
		}
	}

	m.wg.Done()
	log.Tracef("External miner speed monitor done")
}

// miningWorkerController launches the worker goroutines that are used to
// generate block templates and solve them.  It also provides the ability to
// dynamically adjust the number of running worker goroutines.
//
// It must be run as a goroutine.
func (m *ExternalMiner) miningWorkerController() {
	ticker := time.NewTicker(time.Second * jobValiditySecs)
	defer ticker.Stop()

out:
	for {
		select {
		case getWorkReq := <-m.getWorkCh:

			//	remove the job that this worker (who is launching this request) is working
			currentJobId := getWorkReq.Params.CurrentJobId
			currentJob, exist := m.activeJobs[currentJobId]
			if exist {
				//	remove the currentJob, since it is becoming an outdated one
				delete(m.activeJobs, currentJobId)

				//	remove the jobId from blockTemplateJobs
				currentSharedBlockTemplateId := currentJob.SharedBlockTemplate.Id()
				jobIdsOnBlockTemplate, ok := m.activeBlockTemplateJobs[currentSharedBlockTemplateId]
				if ok {
					delete(jobIdsOnBlockTemplate, currentJobId)

					if len(jobIdsOnBlockTemplate) == 0 {
						// all the jobs related to this blockTemplate has been deleted
						if m.latestBlockTemplate != nil &&
							strings.Compare(currentSharedBlockTemplateId, m.latestBlockTemplate.Id()) != 0 {
							// this blockTemplate will not be used by a new job any more
							delete(m.activeBlockTemplates, currentSharedBlockTemplateId)
							delete(m.activeBlockTemplateJobs, currentSharedBlockTemplateId)
						}
					}
				}
			}

			//	produce a new job

			// Only if there is a connection to at least one other peer, it makes sense to distribute job
			// since there is no way to relay a found block or receive
			// transactions to work on when there are no connected peers.
			if m.cfg.ConnectedCount() == 0 {
				err := errors.New("no peer connected, no need to mine")
				getWorkReq.Err <- err
				getWorkReq.Result <- nil
			} else {
				m.submitBlockLock.Lock()

				curHeight := m.g.BestSnapshot().Height
				if curHeight != 0 && !m.cfg.IsCurrent() {
					err := errors.New("the tip of local chain is not current, please try again later")
					getWorkReq.Err <- err
					getWorkReq.Result <- nil

					m.submitBlockLock.Unlock()
				} else {
					generateNewTemplate := false

					if m.latestBlockTemplate == nil {
						generateNewTemplate = true
					} else {
						best := m.g.BestSnapshot()
						if !m.latestBlockTemplate.BlockTemplate.BlockAbe.Header.PrevBlock.IsEqual(&best.Hash) {
							//	all activate blockTemplates and jobs are outdated, shall be cleaned
							m.activeBlockTemplates = make(map[string]*SharedBlockTemplate)
							m.activeJobs = make(map[string]*Job)
							m.activeBlockTemplateJobs = make(map[string]map[string]struct{})

							m.latestBlockTemplate = nil
							generateNewTemplate = true
						} else if m.g.TxSource().LastUpdated().After(m.latestBlockTemplate.BlockTemplate.BlockAbe.Header.Timestamp) {
							// The mempool is updated after the last update of timestamp of latestBlockTemplate.
							// Generating a new block template as the latestBlockTemplate to guarantee it is consistent with the mempool:
							// (1) if new transactions are added into the mempool, the new latestBlockTemplate may collect the new transactions;
							// (2) if some previous transactions are removed from mempool due to some reasons, such as fade, such a generation will guarantee that the latestBlockTemplate is consistent with the mempool.
							//	But at such a moment, externalMiner does not clean the existing blockTempaltes or jobs, while leaving this to timeSticker, although they may have been outdated.
							//	Since actually, accurate judgement on whether a blockTemplate's transactions are outdated to the mempool is expensive.
							generateNewTemplate = true
						} else {
							//	just update the timestamp of the latestBlockTemplate
							generateNewTemplate = false
							m.g.UpdateBlockTimeAbeEthash(m.latestBlockTemplate.BlockTemplate)
							// note that for mainnet, this just updates timestamp,
							// while in testnet or simnet, this may update the Bits field, depends on m.cfg.ChainParams.ReduceMinDifficulty
							if m.cfg.ChainParams.ReduceMinDifficulty {
								m.latestBlockTemplate.EraseCachedId()
							}
						}
					}

					generateNewJob := false
					if generateNewTemplate {
						// Choose a payment address at random.
						masterAddr := m.cfg.MiningAddrBytes

						// Create a new block template using the available transactions
						// in the memory pool as a source of transactions to potentially
						// include in the block.
						newTemplate, err := m.g.NewBlockTemplate(masterAddr)
						if err != nil {
							getWorkReq.Err <- err
							getWorkReq.Result <- nil
							generateNewJob = false
						} else {
							m.latestBlockTemplate = NewSharedBlockTemplate(newTemplate)
							m.activeBlockTemplates[m.latestBlockTemplate.Id()] = m.latestBlockTemplate
							m.activeBlockTemplateJobs[m.latestBlockTemplate.Id()] = make(map[string]struct{})
							generateNewJob = true
						}
					}
					m.submitBlockLock.Unlock()

					if generateNewJob == true {
						//	new job based on the latestBlockTemplate
						contentHash := m.latestBlockTemplate.BlockTemplate.BlockAbe.Header.ContentHash()
						if bytes.Compare(contentHash[:], m.latestContentHash[:]) != 0 {
							m.latestContentHash = contentHash
							m.latestExtraNonce = 0
						} else {
							m.latestExtraNonce = m.latestExtraNonce + 1
							//	Note that for each GetWorkReq request, the latestBlockTemplate either is a newly generated one, or update its timestamp in header,
							//	so that two GetWorkReq request share the same latestContentHash only if the two corresponding latestBlockTemplate share the same timestamp due to the precision of timestamp.
							//	Further, it is almost impossible that 2^16 GetWorkReq requests shares the same latestContentHash, which means 2^16 GetWorkReq requests arrived and are handled at the same time (precision).
							//	Thus, here we just take it as never happened.
							//	If it happened, the Result is that some computation 'may' be wasted. (If the miner start from a random nonce, the probability will be further reduced)
							//	Note that m.latestExtraNonce is defined as uint16, so that 65535+1 will Result 0.
						}
						targetBoundary := blockchain.CompactToBig(m.latestBlockTemplate.BlockTemplate.BlockAbe.Header.Bits)

						newJob := NewJob(m.latestBlockTemplate, m.latestBlockTemplate.BlockTemplate.BlockAbe.Header.Timestamp, m.latestContentHash, m.latestExtraNonce, targetBoundary, time.Now())
						m.activeJobs[newJob.Id()] = newJob
						m.activeBlockTemplateJobs[newJob.SharedBlockTemplate.Id()][newJob.Id()] = struct{}{}

						getWorkReq.Err <- nil
						getWorkReq.Result <- newJob
					}
				}
			}

		case submitWorkReq := <-m.submitWorkCh:
			job, ok := m.activeJobs[submitWorkReq.params.JobId]
			if !ok {
				err := errors.New("the target job is not in the active job set")
				submitWorkReq.err <- err
			} else if bytes.Compare(submitWorkReq.params.ContentHash[:], job.ContentHash[:]) != 0 {
				err := errors.New("the content hash does not match that of the corresponding active job")
				submitWorkReq.err <- err
			} else if submitWorkReq.params.ExtraNonce != job.ExtraNonce {
				err := errors.New("the extraNonce does not match that of the corresponding active job")
				submitWorkReq.err <- err
			} else if ethash.VerifySealFast(submitWorkReq.params.ContentHash, submitWorkReq.params.Nonce, submitWorkReq.params.MixDigest, job.TargetBoundary) == true {
				//	check the validity of (nonce, mixDigest) to prevent DOS attack
				job.SharedBlockTemplate.BlockTemplate.BlockAbe.Header.NonceExt = submitWorkReq.params.Nonce
				job.SharedBlockTemplate.BlockTemplate.BlockAbe.Header.MixDigest = submitWorkReq.params.MixDigest
				block := abeutil.NewBlockAbe(job.SharedBlockTemplate.BlockTemplate.BlockAbe)
				//	exterminer is implemented after the EthashPoW is implemented. For simplicity, we only call submitBlockEthash().
				m.submitBlockEthash(block)
				//	even if m.submitBlockEthash(block) return false, for external miner, the submitWorkReq submits a valid solution.
				submitWorkReq.err <- nil
			} else {
				err := errors.New("the (nonce, mixDigest) does not match the target boundary of the corresponding active job")
				submitWorkReq.err <- err
			}

		case <-ticker.C:
			toDelJobId := make([]string, 0, len(m.activeJobs))
			for jobId, job := range m.activeJobs {
				if time.Since(job.DistributedTime).Seconds() > jobValiditySecs {
					//	the job was assigned to a worker who has not request new jobs for jobValiditySecs seconds,
					//	so it is assumed that the job has been given up by the worker.
					toDelJobId = append(toDelJobId, jobId)
				}
			}

			for i := 0; i < len(toDelJobId); i++ {
				jobId := toDelJobId[i]
				sharedBlockTemplateId := m.activeJobs[jobId].SharedBlockTemplate.Id()

				delete(m.activeJobs, jobId)

				//	remove the jobId from blockTemplateJobs
				jobIdsOnBlockTemplate, ok := m.activeBlockTemplateJobs[sharedBlockTemplateId]
				if ok {
					delete(jobIdsOnBlockTemplate, jobId)

					if len(jobIdsOnBlockTemplate) == 0 {
						// all the jobs related to this blockTemplate has been deleted
						if m.latestBlockTemplate != nil &&
							strings.Compare(sharedBlockTemplateId, m.latestBlockTemplate.Id()) != 0 {
							// this blockTemplate will not be used by a new job any more
							delete(m.activeBlockTemplates, sharedBlockTemplateId)
							delete(m.activeBlockTemplateJobs, sharedBlockTemplateId)
						}
					}
				}
			}

		case <-m.quit:
			break out
		}
	}

	//	free all blockTemplates, jobs, ...
	//	todo: Is this necessary?
	m.latestBlockTemplate = nil
	m.activeBlockTemplates = nil
	m.activeJobs = nil
	m.activeBlockTemplateJobs = nil
	m.workerHashRates = nil

	// stop the speed monitor since
	close(m.speedMonitorQuit)
	m.wg.Done()
}

func (m *ExternalMiner) submitBlockEthash(block *abeutil.BlockAbe) bool {
	m.submitBlockLock.Lock()
	defer m.submitBlockLock.Unlock()

	// Ensure the block is not stale since a new block could have shown up
	// while the solution was being found. Typically that condition is
	// detected and all work on the stale block is halted to start work on
	// a new block, but the check only happens periodically, so it is
	// possible a block was found and submitted in between.
	msgBlock := block.MsgBlock()
	if !msgBlock.Header.PrevBlock.IsEqual(&m.g.BestSnapshot().Hash) {
		log.Debugf("Block submitted via external miner with previous "+
			"block %s is stale", msgBlock.Header.PrevBlock)
		return false
	}

	// Process this block using the same rules as blocks coming from other
	// nodes.  This will in turn relay it to the network like normal.
	isOrphan, err := m.cfg.ProcessBlock(block, blockchain.BFNone)
	if err != nil {
		// Anything other than a rule violation is an unexpected error,
		// so log that error as an internal error.
		if _, ok := err.(blockchain.RuleError); !ok {
			log.Errorf("Unexpected error while processing "+
				"block submitted via external miner: %v", err)
			return false
		}

		log.Debugf("Block submitted via external miner rejected: %v", err)
		return false
	}
	if isOrphan {
		log.Debugf("Block submitted via external miner is an orphan")
		return false
	}

	// The block was accepted.

	//	in pqringct-Abelian, the TxFee field of CoinbaseTx is used to store the invalue
	inValue := block.MsgBlock().Transactions[0].TxFee
	log.Infof("Block submitted via external miner accepted (hash %v, "+"seal Hash %v, "+"height %d, "+
		"amount %v)", block.Hash(), ethash.SealHash(&block.MsgBlock().Header), block.Height(), abeutil.Amount(inValue))
	return true
}

// Start begins the external mining process as well as the speed monitor used to
// track hashing metrics.  Calling this function when the external miner has
// already been started will have no effect.
//
// This function is safe for concurrent access.
func (m *ExternalMiner) Start() {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is already running.
	if m.started {
		return
	}

	m.getWorkCh = make(chan *GetWorkReq)
	m.submitWorkCh = make(chan *submitWorkReq)
	m.submitHashRateCh = make(chan *submitHashRateReq)
	m.queryHashRate = make(chan float64)

	m.latestBlockTemplate = nil
	m.activeBlockTemplates = make(map[string]*SharedBlockTemplate)
	m.activeJobs = make(map[string]*Job)
	m.activeBlockTemplateJobs = make(map[string]map[string]struct{})
	m.workerHashRates = make(map[string]*WorkerHashRate)

	m.quit = make(chan struct{})
	m.speedMonitorQuit = make(chan struct{})
	m.wg.Add(2)

	//	speedMonitor and miningWorkerController will operate the global fields of m,
	//	so that there should be only one speedMonitor and only one miningWorkerController
	go m.speedMonitor()
	go m.miningWorkerController()

	m.started = true
	log.Infof("External miner started")
}

// Stop gracefully stops the mining process by signalling all workers, and the
// speed monitor to quit.  Calling this function when the CPU miner has not
// already been started will have no effect.
//
// This function is safe for concurrent access.
func (m *ExternalMiner) Stop() {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is not currently running or if running in
	// discrete mode (using GenerateNBlocks).
	if !m.started {
		return
	}

	close(m.quit)
	m.wg.Wait()
	m.started = false
	log.Infof("External miner stopped")
}

// IsMining returns whether or not the external miner has been started and is
// therefore currenting mining.
//
// This function is safe for concurrent access.
func (m *ExternalMiner) IsMining() bool {
	m.Lock()
	defer m.Unlock()

	return m.started
}

// HashesPerSecond returns the number of hashes per second the mining process
// is performing.  0 is returned if the miner is not currently running.
//
// This function is safe for concurrent access.
func (m *ExternalMiner) HashRate() float64 {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is not currently running.
	if !m.started {
		return 0
	}

	return <-m.queryHashRate
}

func (m *ExternalMiner) HandleGetWorkReq(req *GetWorkReq) {
	m.getWorkCh <- req
}

// New returns a new instance of a CPU miner for the provided configuration.
// Use Start to begin the mining process.  See the documentation for CPUMiner
// type for more details.
func New(cfg *Config) *ExternalMiner {
	return &ExternalMiner{
		g:      cfg.BlockTemplateGenerator,
		ethash: cfg.Ethash,
		cfg:    *cfg,
	}
}
