package ethash

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"golang.org/x/crypto/sha3"
	"math/big"
	"runtime"
	"testing"
	"time"
)

func TestCalcSizes(t *testing.T) {
	cacheSize0 := calcCacheSize(0)
	datasetSize0 := calcDatasetSize(0)
	fmt.Println("cache size for epoch 0: ", cacheSize0)
	fmt.Println("dats set size for epoch 0: ", datasetSize0)

	i := 0
	for i = 0; i < maxEpoch; i++ {
		if cacheSizes[i] == cacheSize0 {
			break
		}
	}

	j := 0
	for j = 0; j < maxEpoch; j++ {
		if datasetSizes[j] == datasetSize0 {
			break
		}
	}
	fmt.Println("i:", i)
	fmt.Println("j:", j)

	for epoch := i; epoch < maxEpoch-i; epoch++ {
		cacheSize := calcCacheSize(epoch - i)
		datasetSize := calcDatasetSize(epoch - i)

		if cacheSizes[epoch] != cacheSize || datasetSizes[epoch] != datasetSize {
			fmt.Println("mismtach on epoch:", epoch)
		}
	}

	ethepoch := int(15173344 / 30000)
	fmt.Println("eth epoch:", ethepoch)
	fmt.Println("eth epoch cache size:", cacheSize(ethepoch))
	fmt.Println("eth epoch dataset size:", datasetSize(ethepoch))
}

func TestEthashSeed(t *testing.T) {
	maxEpoch := 10240
	seedMap := make(map[string]int)
	seedheadMap := make(map[string]int)
	for epoch := 0; epoch < maxEpoch; epoch++ {
		ethseed := ethashSeed(epoch)
		key := hex.EncodeToString(ethseed)
		seedMap[key] = epoch

		//keyHead := string(ethseed[:8])
		keyHead := hex.EncodeToString(ethseed[:32])
		seedheadMap[keyHead] = epoch
		//fmt.Println(ethashSeed(epoch))
	}

	fmt.Println("length of seed map:", len(seedMap))
	fmt.Println("length of seedhead map:", len(seedheadMap))
	if len(seedMap) != maxEpoch {
		fmt.Println("there are repeated seeds")
	}
	if len(seedheadMap) != maxEpoch {
		fmt.Println("there are repeated seed heads")
	}
}

func TestMakeCache(t *testing.T) {
	MakeCache(515, "test")
}

func TestMakeDataset(t *testing.T) {
	MakeDataset(512, "test")
}

func TestMakeDatasetMultiple(t *testing.T) {
	ethash := New(DefaultCfg)

	ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	fmt.Println("Start on: ", time.Now())

	epoch := 0
	fmt.Println("epoch:", epoch)
	dataset0 := ethash.dataset(epoch, true)
	fmt.Println(len(dataset0.dataset))

	epoch = 1
	fmt.Println("epoch:", epoch)
	dataset1 := ethash.dataset(epoch, true)
	fmt.Println(len(dataset1.dataset))

	epoch = 2
	fmt.Println("epoch:", epoch)
	dataset2 := ethash.dataset(epoch, true)
	fmt.Println(len(dataset2.dataset))

	//epoch = 3
	//fmt.Println("epoch:", epoch)
	//dataset3 := ethash.dataset(epoch, true)
	//fmt.Println(len(dataset3.dataset))

	for {
		select {
		case <-ticker.C:
			n := 0
			if dataset0.generated() {
				fmt.Println("dataset 0 generated: ", time.Now(), "len=", len(dataset0.dataset))
				n += 1
			}
			if dataset1.generated() {
				fmt.Println("dataset 1 generated: ", time.Now(), "len=", len(dataset1.dataset))
				n += 2
			}
			if dataset2.generated() {
				fmt.Println("dataset 2 generated: ", time.Now(), "len=", len(dataset2.dataset))
				n += 3
			}

			//if dataset3.generated() {
			//	fmt.Println("dataset 3 generated: ", time.Now(), "len=", len(dataset3.dataset))
			//	n += 4
			//}

		default:
		}
	}
}

func TestHashimoto(t *testing.T) {
	ethash := New(DefaultCfg)

	contentHash := chainhash.ChainHash([]byte("test"))

	//epoch := 1
	epoch := 1
	cache := ethash.cache(epoch)
	size := datasetSize(epoch)

	start := time.Now()
	dataset := ethash.dataset(epoch, false)
	elpased := time.Since(start)
	fmt.Println("Time for loading dataset:", elpased)

	start = time.Now()
	for i := uint64(0); i < 100; i++ {

		digestFull, sealHashFull := hashimotoFull(dataset.dataset, contentHash, i)

		digest, sealHash := hashimotoLight(size, cache.cache, contentHash, i)

		if bytes.Compare(digestFull, digest) != 0 {
			fmt.Println("mismatched disgest on i:", i)
		}

		if bytes.Compare(sealHashFull[:], sealHash[:]) != 0 {
			fmt.Println("mismatched hash on i:", i)
		}
	}

	fmt.Println("Time for 100 Full Hash and light hash:", time.Since(start))

	start = time.Now()
	for i := uint64(10000001); i < uint64(10000009); i++ {
		//fmt.Println("i:", i)
		hashimotoLight(size, cache.cache, contentHash, i)
	}
	elpased = time.Since(start)
	fmt.Println("Time for 10000000 Light Hash:", elpased)

	start = time.Now()
	for i := uint64(10000001); i < uint64(10000009); i++ {
		//fmt.Println("i:", i)
		hashimotoFull(dataset.dataset, contentHash, i)
	}
	elpased = time.Since(start)
	fmt.Println("Time for 10000000 Full Hash:", elpased)

	start = time.Now()
	for i := uint64(10000001); i < uint64(10000009); i++ {
		//fmt.Println("i:", i)
		seedTmp := make([]byte, chainhash.HashSize+8)
		copy(seedTmp, contentHash[:])
		binary.LittleEndian.PutUint64(seedTmp[chainhash.HashSize:], i)

		chainhash.DoubleHashH(seedTmp)
	}
	elpased = time.Since(start)
	fmt.Println("Time for 10000000 DoubleHash:", elpased)

	runtime.KeepAlive(dataset)
	runtime.KeepAlive(cache)
}

func TestSHA3256(t *testing.T) {
	hash256 := sha3.Sum256(nil)
	hashDisplay256 := hex.EncodeToString(hash256[:])
	fmt.Println(hashDisplay256)

	var a chainhash.Hash
	a = hash256
	fmt.Println(a)

	hash512 := sha3.Sum512(nil)
	hashDisplay512 := hex.EncodeToString(hash512[:])
	fmt.Println(hashDisplay512)

}

func TestSHA3(t *testing.T) {
	test_text := []byte("As Estha stirred the thick jam he thought Two Thoughts and the Two Thoughts he thought were these: a) Anything can happen to anyone. and b) It is best to be prepared.")
	for i := 0; i < 167; i++ {
		hash256 := sha3.Sum256(test_text[:i])
		hash512 := sha3.Sum512(test_text[:i])
		fmt.Println("{ ", i, ", \"", hex.EncodeToString(hash256[:]), "\", \"", hex.EncodeToString(hash512[:]), "\" }")
	}
}

func TestSHA3_keccak(t *testing.T) {
	input := []byte("the seed string for cache and dataset")
	fmt.Println(len(input))
	hash := sha3.Sum256(input[:])
	fmt.Println(input[:])
	str := hex.EncodeToString(hash[:])

	fmt.Println(str)
}

func TestCacheSizesGenerate(t *testing.T) {
	fmt.Println("cache size:")
	cacheLocalSizes := [maxEpoch]uint64{}
	for i := 0; i < maxEpoch; i++ {
		size := calcCacheSize(i)
		cacheLocalSizes[i] = size
		fmt.Print(size)
		if (i+1)%8 == 0 {
			fmt.Println(", ")
		} else {
			fmt.Print(", ")
		}
	}

	fmt.Println("dataset size:")
	datasetLocalSizes := [maxEpoch]uint64{}
	for i := 0; i < maxEpoch; i++ {
		size := calcDatasetSize(i)
		datasetLocalSizes[i] = size
		fmt.Print(size)
		if (i+1)%8 == 0 {
			fmt.Println(", ")
		} else {
			fmt.Print(", ")
		}
	}

	for i := 0; i < maxEpoch; i++ {
		if cacheSizes[i] == cacheLocalSizes[0] {
			fmt.Println("eth epoch cache:", i, "equals abel epoch 0")
			break
		}
	}

	for i := 0; i < maxEpoch; i++ {
		if datasetSizes[i] == datasetLocalSizes[0] {
			fmt.Println("eth epoch dataset:", i, "equals abel epoch 0")
			break
		}
	}

	diff := 512
	for i := 0; i < maxEpoch; i++ {
		if cacheLocalSizes[i] != calcCacheSizeEth(diff+2*i) {
			fmt.Println("cache: abel epoch size", i, "does not match eth epoch %d", diff+2*i)
		}
	}
	for i := 0; i < maxEpoch; i++ {
		if datasetLocalSizes[i] != calcDatasetSizeEth(diff+2*i) {
			fmt.Println("dataset: abel epoch", i, "does not match eth epoch %d", diff+2*i)
		}
	}
}

func calcCacheSizeEth(epoch int) uint64 {
	size := cacheInitBytes/5 + cacheGrowthBytes/2*uint64(epoch) - hashBytes
	//	To be safe, we use ProablyPrime(32) rather than ProablyPrime(1) as in Ethereum.
	for !new(big.Int).SetUint64(size / hashBytes).ProbablyPrime(32) { // Always accurate for n < 2^64
		size -= 2 * hashBytes
	}
	return size
}

func calcDatasetSizeEth(epoch int) uint64 {
	size := datasetInitBytes/5 + datasetGrowthBytes/2*uint64(epoch) - mixBytes
	//	To be safe, we use ProablyPrime(32) rather than ProablyPrime(1) as in Ethereum.
	for !new(big.Int).SetUint64(size / mixBytes).ProbablyPrime(32) { // Always accurate for n < 2^64
		size -= 2 * mixBytes
	}
	return size
}

//	TestAbelEthashSizes() tests the consistence of the content of datasetSizesEth[] and datasetSizes[], as well as cacheSizesEth[] and cacheSizes[].
//func TestAbelEthashSizes(t *testing.T) {
//	for i := 0; i < maxEpoch; i++ {
//		if cacheSizesEth[i] == cacheSizes[0] {
//			fmt.Println("cache: eth epoch ", i, "equals abel epoch 0")
//		}
//	}
//
//	for i := 0; i < maxEpoch; i++ {
//		if datasetSizesEth[i] == datasetSizes[0] {
//			fmt.Println("dataset: eth epoch ", i, "equals abel epoch 0")
//		}
//	}
//
//	diff := 512
//	for i := 0; i < maxEpoch; i++ {
//		if cacheSizes[i] != calcCacheSizeEth(diff+2*i) {
//			fmt.Println("cache: abel epoch size", i, "does not match eth epoch %d", diff+2*i)
//		}
//	}
//	for i := 0; i < maxEpoch; i++ {
//		if datasetSizes[i] != calcDatasetSizeEth(diff+2*i) {
//			fmt.Println("dataset: abel epoch", i, "does not match eth epoch %d", diff+2*i)
//		}
//	}
//
//	i := 0
//	for i = 0; diff+2*i < maxEpoch; i++ {
//		if cacheSizes[i] != cacheSizesEth[diff+2*i] {
//			fmt.Println("cache: abel epoch size", i, "does not match eth epoch %d", diff+2*i)
//		}
//	}
//	fmt.Println("cache: i", i, "diff+2*i:", diff+2*i)
//
//	for i = 0; diff+2*i < maxEpoch; i++ {
//		if datasetSizes[i] != datasetSizesEth[diff+2*i] {
//			fmt.Println("dataset: abel epoch", i, "does not match eth epoch %d", diff+2*i)
//		}
//	}
//	fmt.Println("dataset: i", i, "diff+2*i:", diff+2*i)
//
//	i = i - 1
//	fmt.Println("dataset: i", i, "diff+2*i:", diff+2*i)
//	fmt.Println("datasetSizes[i]:", datasetSizes[i])
//	fmt.Println("datasetSizesEth[diff+2*i]:", datasetSizesEth[diff+2*i])
//}

func TestCachandDataSetSize(t *testing.T) {
	for i := 0; i < 2048; i++ {
		fmt.Println("{", i, ",", cacheSize(i), ",", datasetSize(i), "},")
	}

	for i := 10240; i < 10243; i++ {
		fmt.Println("{", i, ",", cacheSize(i), ",", datasetSize(i), "},")
	}
}

func TestGenerateEthashSeed(t *testing.T) {
	i := 0
	hash := ethashSeed(i)
	fmt.Println(hex.EncodeToString(hash))
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")

	i = 1
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")

	i = 2
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")

	i = 10
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")

	i = 11
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")

	i = 101
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")

	i = 102
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")

	i = 2047
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")
	i = 2048
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")
	i = 2049
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")

	i = 10239
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")

	i = 10240
	fmt.Println("{", i, ",", "\"", hex.EncodeToString(ethashSeed(i)), "\"},")
}

func TestCache(t *testing.T) {
	epoch := 2047
	size := cacheSize(epoch)
	seed := ethashSeed(epoch)
	cache := make([]uint32, size/4)
	generateCache(cache, epoch, seed)
	buf := make([]byte, size)

	j := 0
	for i := uint64(0); i < size/4; i++ {
		buf[j+3] = byte(cache[i])
		buf[j+2] = byte(cache[i] >> 8)
		buf[j+1] = byte(cache[i] >> 16)
		buf[j] = byte(cache[i] >> 24)

		j += 4
	}

	hash := sha3.Sum256(buf)

	fmt.Println(hex.EncodeToString(hash[:]))

}

func TestLightCache(t *testing.T) {
	blockheight := 585005

	hashBytes, err := hex.DecodeString("53a005f209a4dc013f022a5078c6b38ced76e767a30367ff64725f23ec652a9f")
	if err != nil {
		fmt.Println(err)
	}
	contentHash, err := chainhash.NewHash(hashBytes)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(hex.EncodeToString(contentHash[:]))

	epoch := (blockheight - wire.BlockHeightEthashPoW) / epochLength

	catcheSize := cacheSize(epoch)
	seed := ethashSeed(epoch)
	cache := make([]uint32, catcheSize/4)
	generateCache(cache, epoch, seed)

	datasetSize := datasetSize(epoch)

	nonce := uint64(0xd337f82001e992c5)
	digest, sealhash := hashimotoLight(datasetSize, cache, *contentHash, nonce)

	fmt.Println("mix hash:", hex.EncodeToString(digest))
	fmt.Println("final hash:", hex.EncodeToString(sealhash[:]))

}
