package rpcclient

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/abesuite/abec/abejson"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

// FutureGenerateResult is a future promise to deliver the result of a
// GenerateAsync RPC invocation (or an applicable error).
type FutureGenerateResult chan *response

// Receive waits for the response promised by the future and returns a list of
// block hashes generated by the call.
func (r FutureGenerateResult) Receive() ([]*chainhash.Hash, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a list of strings.
	var result []string
	err = json.Unmarshal(res, &result)
	if err != nil {
		return nil, err
	}

	// Convert each block hash to a chainhash.Hash and store a pointer to
	// each.
	convertedResult := make([]*chainhash.Hash, len(result))
	for i, hashString := range result {
		convertedResult[i], err = chainhash.NewHashFromStr(hashString)
		if err != nil {
			return nil, err
		}
	}

	return convertedResult, nil
}

// GenerateAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See Generate for the blocking version and more details.
func (c *Client) GenerateAsync(numBlocks uint32) FutureGenerateResult {
	cmd := abejson.NewGenerateCmd(numBlocks)
	return c.sendCmd(cmd)
}

// Generate generates numBlocks blocks and returns their hashes.
func (c *Client) Generate(numBlocks uint32) ([]*chainhash.Hash, error) {
	return c.GenerateAsync(numBlocks).Receive()
}

// FutureGenerateToAddressResult is a future promise to deliver the result of a
// GenerateToAddressResult RPC invocation (or an applicable error).
type FutureGenerateToAddressResult chan *response

// Receive waits for the response promised by the future and returns the hashes of
// of the generated blocks.
func (f FutureGenerateToAddressResult) Receive() ([]*chainhash.Hash, error) {
	res, err := receiveFuture(f)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a list of strings.
	var result []string
	err = json.Unmarshal(res, &result)
	if err != nil {
		return nil, err
	}

	// Convert each block hash to a chainhash.Hash and store a pointer to
	// each.
	convertedResult := make([]*chainhash.Hash, len(result))
	for i, hashString := range result {
		convertedResult[i], err = chainhash.NewHashFromStr(hashString)
		if err != nil {
			return nil, err
		}
	}

	return convertedResult, nil
}

// GenerateToAddressAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GenerateToAddress for the blocking version and more details.
func (c *Client) GenerateToAddressAsync(numBlocks int64, address abeutil.Address, maxTries *int64) FutureGenerateToAddressResult {
	cmd := abejson.NewGenerateToAddressCmd(numBlocks, address.EncodeAddress(), maxTries)
	return c.sendCmd(cmd)
}

// GenerateToAddress generates numBlocks blocks to the given address and returns their hashes.
func (c *Client) GenerateToAddress(numBlocks int64, address abeutil.Address, maxTries *int64) ([]*chainhash.Hash, error) {
	return c.GenerateToAddressAsync(numBlocks, address, maxTries).Receive()
}

// FutureGetGenerateResult is a future promise to deliver the result of a
// GetGenerateAsync RPC invocation (or an applicable error).
type FutureGetGenerateResult chan *response

// Receive waits for the response promised by the future and returns true if the
// server is set to mine, otherwise false.
func (r FutureGetGenerateResult) Receive() (bool, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return false, err
	}

	// Unmarshal result as a boolean.
	var result bool
	err = json.Unmarshal(res, &result)
	if err != nil {
		return false, err
	}

	return result, nil
}

// GetGenerateAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetGenerate for the blocking version and more details.
func (c *Client) GetGenerateAsync() FutureGetGenerateResult {
	cmd := abejson.NewGetGenerateCmd()
	return c.sendCmd(cmd)
}

// GetGenerate returns true if the server is set to mine, otherwise false.
func (c *Client) GetGenerate() (bool, error) {
	return c.GetGenerateAsync().Receive()
}

// FutureSetGenerateResult is a future promise to deliver the result of a
// SetGenerateAsync RPC invocation (or an applicable error).
type FutureSetGenerateResult chan *response

// Receive waits for the response promised by the future and returns an error if
// any occurred when setting the server to generate coins (mine) or not.
func (r FutureSetGenerateResult) Receive() error {
	_, err := receiveFuture(r)
	return err
}

// SetGenerateAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See SetGenerate for the blocking version and more details.
func (c *Client) SetGenerateAsync(enable bool, numCPUs int) FutureSetGenerateResult {
	cmd := abejson.NewSetGenerateCmd(enable, &numCPUs)
	return c.sendCmd(cmd)
}

// SetGenerate sets the server to generate coins (mine) or not.
func (c *Client) SetGenerate(enable bool, numCPUs int) error {
	return c.SetGenerateAsync(enable, numCPUs).Receive()
}

// FutureGetHashesPerSecResult is a future promise to deliver the result of a
// GetHashesPerSecAsync RPC invocation (or an applicable error).
type FutureGetHashesPerSecResult chan *response

// Receive waits for the response promised by the future and returns a recent
// hashes per second performance measurement while generating coins (mining).
// Zero is returned if the server is not mining.
func (r FutureGetHashesPerSecResult) Receive() (int64, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return -1, err
	}

	// Unmarshal result as an int64.
	var result int64
	err = json.Unmarshal(res, &result)
	if err != nil {
		return 0, err
	}

	return result, nil
}

// GetHashesPerSecAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetHashesPerSec for the blocking version and more details.
func (c *Client) GetHashesPerSecAsync() FutureGetHashesPerSecResult {
	cmd := abejson.NewGetHashesPerSecCmd()
	return c.sendCmd(cmd)
}

// GetHashesPerSec returns a recent hashes per second performance measurement
// while generating coins (mining).  Zero is returned if the server is not
// mining.
func (c *Client) GetHashesPerSec() (int64, error) {
	return c.GetHashesPerSecAsync().Receive()
}

// FutureGetMiningInfoResult is a future promise to deliver the result of a
// GetMiningInfoAsync RPC invocation (or an applicable error).
type FutureGetMiningInfoResult chan *response

// Receive waits for the response promised by the future and returns the mining
// information.
func (r FutureGetMiningInfoResult) Receive() (*abejson.GetMiningInfoResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a getmininginfo result object.
	var infoResult abejson.GetMiningInfoResult
	err = json.Unmarshal(res, &infoResult)
	if err != nil {
		return nil, err
	}

	return &infoResult, nil
}

// GetMiningInfoAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetMiningInfo for the blocking version and more details.
func (c *Client) GetMiningInfoAsync() FutureGetMiningInfoResult {
	cmd := abejson.NewGetMiningInfoCmd()
	return c.sendCmd(cmd)
}

// GetMiningInfo returns mining information.
func (c *Client) GetMiningInfo() (*abejson.GetMiningInfoResult, error) {
	return c.GetMiningInfoAsync().Receive()
}

// FutureGetNetworkHashPS is a future promise to deliver the result of a
// GetNetworkHashPSAsync RPC invocation (or an applicable error).
type FutureGetNetworkHashPS chan *response

// Receive waits for the response promised by the future and returns the
// estimated network hashes per second for the block heights provided by the
// parameters.
func (r FutureGetNetworkHashPS) Receive() (int64, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return -1, err
	}

	// Unmarshal result as an int64.
	var result int64
	err = json.Unmarshal(res, &result)
	if err != nil {
		return 0, err
	}

	return result, nil
}

// GetNetworkHashPSAsync returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetNetworkHashPS for the blocking version and more details.
func (c *Client) GetNetworkHashPSAsync() FutureGetNetworkHashPS {
	cmd := abejson.NewGetNetworkHashPSCmd(nil, nil)
	return c.sendCmd(cmd)
}

// GetNetworkHashPS returns the estimated network hashes per second using the
// default number of blocks and the most recent block height.
//
// See GetNetworkHashPS2 to override the number of blocks to use and
// GetNetworkHashPS3 to override the height at which to calculate the estimate.
func (c *Client) GetNetworkHashPS() (int64, error) {
	return c.GetNetworkHashPSAsync().Receive()
}

// GetNetworkHashPS2Async returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetNetworkHashPS2 for the blocking version and more details.
func (c *Client) GetNetworkHashPS2Async(blocks int) FutureGetNetworkHashPS {
	cmd := abejson.NewGetNetworkHashPSCmd(&blocks, nil)
	return c.sendCmd(cmd)
}

// GetNetworkHashPS2 returns the estimated network hashes per second for the
// specified previous number of blocks working backwards from the most recent
// block height.  The blocks parameter can also be -1 in which case the number
// of blocks since the last difficulty change will be used.
//
// See GetNetworkHashPS to use defaults and GetNetworkHashPS3 to override the
// height at which to calculate the estimate.
func (c *Client) GetNetworkHashPS2(blocks int) (int64, error) {
	return c.GetNetworkHashPS2Async(blocks).Receive()
}

// GetNetworkHashPS3Async returns an instance of a type that can be used to get
// the result of the RPC at some future time by invoking the Receive function on
// the returned instance.
//
// See GetNetworkHashPS3 for the blocking version and more details.
func (c *Client) GetNetworkHashPS3Async(blocks, height int) FutureGetNetworkHashPS {
	cmd := abejson.NewGetNetworkHashPSCmd(&blocks, &height)
	return c.sendCmd(cmd)
}

// GetNetworkHashPS3 returns the estimated network hashes per second for the
// specified previous number of blocks working backwards from the specified
// block height.  The blocks parameter can also be -1 in which case the number
// of blocks since the last difficulty change will be used.
//
// See GetNetworkHashPS and GetNetworkHashPS2 to use defaults.
func (c *Client) GetNetworkHashPS3(blocks, height int) (int64, error) {
	return c.GetNetworkHashPS3Async(blocks, height).Receive()
}

// FutureGetWork is a future promise to deliver the result of a
// GetWorkAsync RPC invocation (or an applicable error).
type FutureGetWork chan *response

// Receive waits for the response promised by the future and returns the hash
// data to work on.
func (r FutureGetWork) Receive() (*abejson.GetWorkResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a getwork result object.
	var result abejson.GetWorkResult
	err = json.Unmarshal(res, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetWorkAsync returns an instance of a type that can be used to get the result
// of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See GetWork for the blocking version and more details.
func (c *Client) GetWorkAsync() FutureGetWork {
	cmd := abejson.NewGetWorkCmd(nil)
	return c.sendCmd(cmd)
}

// GetWork returns hash data to work on.
//
// See GetWorkSubmit to submit the found solution.
func (c *Client) GetWork() (*abejson.GetWorkResult, error) {
	return c.GetWorkAsync().Receive()
}

// FutureGetWorkSubmit is a future promise to deliver the result of a
// GetWorkSubmitAsync RPC invocation (or an applicable error).
type FutureGetWorkSubmit chan *response

// Receive waits for the response promised by the future and returns whether
// or not the submitted block header was accepted.
func (r FutureGetWorkSubmit) Receive() (bool, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return false, err
	}

	// Unmarshal result as a boolean.
	var accepted bool
	err = json.Unmarshal(res, &accepted)
	if err != nil {
		return false, err
	}

	return accepted, nil
}

//// GetWorkSubmitAsync returns an instance of a type that can be used to get the
//// result of the RPC at some future time by invoking the Receive function on the
//// returned instance.
////
//// See GetWorkSubmit for the blocking version and more details.
//func (c *Client) GetWorkSubmitAsync(data string) FutureGetWorkSubmit {
//	cmd := abejson.NewGetWorkCmd(&data)
//	return c.sendCmd(cmd)
//}
//
//// GetWorkSubmit submits a block header which is a solution to previously
//// requested data and returns whether or not the solution was accepted.
////
//// See GetWork to request data to work on.
//func (c *Client) GetWorkSubmit(data string) (bool, error) {
//	return c.GetWorkSubmitAsync(data).Receive()
//}

// FutureSubmitBlockResult is a future promise to deliver the result of a
// SubmitBlockAsync RPC invocation (or an applicable error).
type FutureSubmitBlockResult chan *response

// Receive waits for the response promised by the future and returns an error if
// any occurred when submitting the block.
func (r FutureSubmitBlockResult) Receive() error {
	res, err := receiveFuture(r)
	if err != nil {
		return err
	}

	if string(res) != "null" {
		var result string
		err = json.Unmarshal(res, &result)
		if err != nil {
			return err
		}

		return errors.New(result)
	}

	return nil

}

// SubmitBlockAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See SubmitBlock for the blocking version and more details.
func (c *Client) SubmitBlockAsync(block *abeutil.Block, options *abejson.SubmitBlockOptions) FutureSubmitBlockResult {
	blockHex := ""
	if block != nil {
		blockBytes, err := block.Bytes()
		if err != nil {
			return newFutureError(err)
		}

		blockHex = hex.EncodeToString(blockBytes)
	}

	cmd := abejson.NewSubmitBlockCmd(blockHex, options)
	return c.sendCmd(cmd)
}

// SubmitBlock attempts to submit a new block into the bitcoin network.
func (c *Client) SubmitBlock(block *abeutil.Block, options *abejson.SubmitBlockOptions) error {
	return c.SubmitBlockAsync(block, options).Receive()
}

// FutureGetBlockTemplateResponse is a future promise to deliver the result of a
// GetBlockTemplateAsync RPC invocation (or an applicable error).
type FutureGetBlockTemplateResponse chan *response

// Receive waits for the Response promised by the future and returns an error if
// any occurred when retrieving the block template.
func (r FutureGetBlockTemplateResponse) Receive() (*abejson.GetBlockTemplateResult, error) {
	res, err := receiveFuture(r)
	if err != nil {
		return nil, err
	}

	// Unmarshal result as a getwork result object.
	var result abejson.GetBlockTemplateResult
	err = json.Unmarshal(res, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// GetBlockTemplateAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See GetBlockTemplate for the blocking version and more details.
func (c *Client) GetBlockTemplateAsync(req *abejson.TemplateRequest) FutureGetBlockTemplateResponse {
	cmd := abejson.NewGetBlockTemplateCmd(req)
	return c.sendCmd(cmd)
}

// GetBlockTemplate returns a new block template for mining.
func (c *Client) GetBlockTemplate(req *abejson.TemplateRequest) (*abejson.GetBlockTemplateResult, error) {
	return c.GetBlockTemplateAsync(req).Receive()
}

// FutureSubmitSimplifiedBlockResult is a future promise to deliver the result of a
// SubmitSimplifiedBlockAsync RPC invocation (or an applicable error).
type FutureSubmitSimplifiedBlockResult chan *response

// Receive waits for the response promised by the future and returns an error if
// any occurred when submitting the block.
func (r FutureSubmitSimplifiedBlockResult) Receive() error {
	res, err := receiveFuture(r)
	if err != nil {
		return err
	}

	if string(res) != "null" {
		var result string
		err = json.Unmarshal(res, &result)
		if err != nil {
			return err
		}

		return errors.New(result)
	}

	return nil
}

// SubmitSimplifiedBlockAsync returns an instance of a type that can be used to get the
// result of the RPC at some future time by invoking the Receive function on the
// returned instance.
//
// See SubmitSimplifiedBlock for the blocking version and more details.
func (c *Client) SubmitSimplifiedBlockAsync(block *wire.MsgSimplifiedBlock, options *abejson.SubmitBlockOptions) FutureSubmitSimplifiedBlockResult {
	blockHex := ""
	var buf bytes.Buffer
	if block != nil {
		err := block.Serialize(&buf)
		if err != nil {
			return newFutureError(err)
		}

		blockHex = hex.EncodeToString(buf.Bytes())
	}

	cmd := abejson.NewSubmitSimplifiedBlockCmd(blockHex, options)
	return c.sendCmd(cmd)
}

// SubmitSimplifiedBlock attempts to submit a new block into the abec network.
func (c *Client) SubmitSimplifiedBlock(block *wire.MsgSimplifiedBlock, options *abejson.SubmitBlockOptions) error {
	return c.SubmitSimplifiedBlockAsync(block, options).Receive()
}
