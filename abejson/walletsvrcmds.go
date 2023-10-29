// NOTE: This file is intended to house the RPC commands that are supported by
// a wallet server.

package abejson

// AddMultisigAddressCmd defines the addmutisigaddress JSON-RPC command.
type AddMultisigAddressCmd struct {
	NRequired int
	Keys      []string
	Account   *string
}
type AddPayeeCmd struct {
	Name         string
	MasterPubKey string
}

// NewAddMultisigAddressCmd returns a new instance which can be used to issue a
// addmultisigaddress JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewAddMultisigAddressCmd(nRequired int, keys []string, account *string) *AddMultisigAddressCmd {
	return &AddMultisigAddressCmd{
		NRequired: nRequired,
		Keys:      keys,
		Account:   account,
	}
}
func NewAddPayeeCmd(name string, masterPubKey string) *AddPayeeCmd {
	return &AddPayeeCmd{
		Name:         name,
		MasterPubKey: masterPubKey,
	}
}

// AddWitnessAddressCmd defines the addwitnessaddress JSON-RPC command.
type AddWitnessAddressCmd struct {
	Address string
}

// NewAddWitnessAddressCmd returns a new instance which can be used to issue a
// addwitnessaddress JSON-RPC command.
func NewAddWitnessAddressCmd(address string) *AddWitnessAddressCmd {
	return &AddWitnessAddressCmd{
		Address: address,
	}
}

// CreateMultisigCmd defines the createmultisig JSON-RPC command.
type CreateMultisigCmd struct {
	NRequired int
	Keys      []string
}

// NewCreateMultisigCmd returns a new instance which can be used to issue a
// createmultisig JSON-RPC command.
func NewCreateMultisigCmd(nRequired int, keys []string) *CreateMultisigCmd {
	return &CreateMultisigCmd{
		NRequired: nRequired,
		Keys:      keys,
	}
}

// DumpPrivKeyCmd defines the dumpprivkey JSON-RPC command.
type DumpPrivKeyCmd struct {
	Address string
}

// NewDumpPrivKeyCmd returns a new instance which can be used to issue a
// dumpprivkey JSON-RPC command.
func NewDumpPrivKeyCmd(address string) *DumpPrivKeyCmd {
	return &DumpPrivKeyCmd{
		Address: address,
	}
}

// EncryptWalletCmd defines the encryptwallet JSON-RPC command.
type EncryptWalletCmd struct {
	Passphrase string
}

// NewEncryptWalletCmd returns a new instance which can be used to issue a
// encryptwallet JSON-RPC command.
func NewEncryptWalletCmd(passphrase string) *EncryptWalletCmd {
	return &EncryptWalletCmd{
		Passphrase: passphrase,
	}
}

// EstimateSmartFeeMode defines the different fee estimation modes available
// for the estimatesmartfee JSON-RPC command.
type EstimateSmartFeeMode string

var (
	EstimateModeUnset        EstimateSmartFeeMode = "UNSET"
	EstimateModeEconomical   EstimateSmartFeeMode = "ECONOMICAL"
	EstimateModeConservative EstimateSmartFeeMode = "CONSERVATIVE"
)

// EstimateSmartFeeCmd defines the estimatesmartfee JSON-RPC command.
type EstimateSmartFeeCmd struct {
	ConfTarget   int64
	EstimateMode *EstimateSmartFeeMode `jsonrpcdefault:"\"CONSERVATIVE\""`
}

// NewEstimateSmartFeeCmd returns a new instance which can be used to issue a
// estimatesmartfee JSON-RPC command.
func NewEstimateSmartFeeCmd(confTarget int64, mode *EstimateSmartFeeMode) *EstimateSmartFeeCmd {
	return &EstimateSmartFeeCmd{
		ConfTarget: confTarget, EstimateMode: mode,
	}
}

// EstimateFeeCmd defines the estimatefee JSON-RPC command.
type EstimateFeeCmd struct {
	NumBlocks int64
}

// NewEstimateFeeCmd returns a new instance which can be used to issue a
// estimatefee JSON-RPC command.
func NewEstimateFeeCmd(numBlocks int64) *EstimateFeeCmd {
	return &EstimateFeeCmd{
		NumBlocks: numBlocks,
	}
}

// EstimatePriorityCmd defines the estimatepriority JSON-RPC command.
type EstimatePriorityCmd struct {
	NumBlocks int64
}

// NewEstimatePriorityCmd returns a new instance which can be used to issue a
// estimatepriority JSON-RPC command.
func NewEstimatePriorityCmd(numBlocks int64) *EstimatePriorityCmd {
	return &EstimatePriorityCmd{
		NumBlocks: numBlocks,
	}
}

// GetAccountCmd defines the getaccount JSON-RPC command.
type GetAccountCmd struct {
	Address string
}

// NewGetAccountCmd returns a new instance which can be used to issue a
// getaccount JSON-RPC command.
func NewGetAccountCmd(address string) *GetAccountCmd {
	return &GetAccountCmd{
		Address: address,
	}
}

// GetAccountAddressCmd defines the getaccountaddress JSON-RPC command.
type GetAccountAddressCmd struct {
	Account string
}

// NewGetAccountAddressCmd returns a new instance which can be used to issue a
// getaccountaddress JSON-RPC command.
func NewGetAccountAddressCmd(account string) *GetAccountAddressCmd {
	return &GetAccountAddressCmd{
		Account: account,
	}
}

// GetAddressesByAccountCmd defines the getaddressesbyaccount JSON-RPC command.
type GetAddressesByAccountCmd struct {
	Account string
}

// NewGetAddressesByAccountCmd returns a new instance which can be used to issue
// a getaddressesbyaccount JSON-RPC command.
func NewGetAddressesByAccountCmd(account string) *GetAddressesByAccountCmd {
	return &GetAddressesByAccountCmd{
		Account: account,
	}
}

// GetBalanceCmd defines the getbalance JSON-RPC command.
type GetBalanceCmd struct {
	Account *string
	MinConf *int `jsonrpcdefault:"1"`
}

// NewGetBalanceCmd returns a new instance which can be used to issue a
// getbalance JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewGetBalanceCmd(account *string, minConf *int) *GetBalanceCmd {
	return &GetBalanceCmd{
		Account: account,
		MinConf: minConf,
	}
}

type AddressMaxSequenceNumberCmd struct{}

func NewAddressCmd() *AddressMaxSequenceNumberCmd {
	return &AddressMaxSequenceNumberCmd{}
}

type AddressRangeCmd struct {
	Start uint64
	End   uint64
}

func NewAddressRangeCmd(start uint64, end uint64) *AddressRangeCmd {
	return &AddressRangeCmd{
		Start: start,
		End:   end,
	}
}

// GetBalancesCmd defines the getbalances JSON-RPC command.
type GetBalancesCmd struct{}
type GenerateAddressCmd struct {
	Num *int `jsonrpcdefault:"1"`
}
type ListFreeAddressesCmd struct {
}
type GetBalancesAbeCmd struct {
	Minconf *int `jsonrpcdefault:"1"`
}

func NewGenerateAddressCmd() *GenerateAddressCmd {
	return &GenerateAddressCmd{}
}
func NewListFreeAddressesCmd() *ListFreeAddressesCmd {
	return &ListFreeAddressesCmd{}
}

// NewGetBalancesCmd returns a new instance which can be used to issue a
// getbalances JSON-RPC command.
func NewGetBalancesCmd() *GetBalancesCmd {
	return &GetBalancesCmd{}
}
func NewGetBalancesAbeCmd(minconf *int) *GetBalancesAbeCmd {
	return &GetBalancesAbeCmd{
		Minconf: minconf,
	}
}

// GetDetailedUtxosCmd defines the getdetailedutxos JSON-RPC command.
type GetDetailedUtxosCmd struct {
	Minconf *int `jsonrpcdefault:"1"`
}

func NewGetDetailedUtxosCmd(minconf *int) *GetDetailedUtxosCmd {
	return &GetDetailedUtxosCmd{
		Minconf: minconf,
	}
}

// GetNewAddressCmd defines the getnewaddress JSON-RPC command.
type GetNewAddressCmd struct {
	Account *string
}

// NewGetNewAddressCmd returns a new instance which can be used to issue a
// getnewaddress JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewGetNewAddressCmd(account *string) *GetNewAddressCmd {
	return &GetNewAddressCmd{
		Account: account,
	}
}

// GetRawChangeAddressCmd defines the getrawchangeaddress JSON-RPC command.
type GetRawChangeAddressCmd struct {
	Account *string
}

// NewGetRawChangeAddressCmd returns a new instance which can be used to issue a
// getrawchangeaddress JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewGetRawChangeAddressCmd(account *string) *GetRawChangeAddressCmd {
	return &GetRawChangeAddressCmd{
		Account: account,
	}
}

// GetReceivedByAccountCmd defines the getreceivedbyaccount JSON-RPC command.
type GetReceivedByAccountCmd struct {
	Account string
	MinConf *int `jsonrpcdefault:"1"`
}

// NewGetReceivedByAccountCmd returns a new instance which can be used to issue
// a getreceivedbyaccount JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewGetReceivedByAccountCmd(account string, minConf *int) *GetReceivedByAccountCmd {
	return &GetReceivedByAccountCmd{
		Account: account,
		MinConf: minConf,
	}
}

// GetReceivedByAddressCmd defines the getreceivedbyaddress JSON-RPC command.
type GetReceivedByAddressCmd struct {
	Address string
	MinConf *int `jsonrpcdefault:"1"`
}

// NewGetReceivedByAddressCmd returns a new instance which can be used to issue
// a getreceivedbyaddress JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewGetReceivedByAddressCmd(address string, minConf *int) *GetReceivedByAddressCmd {
	return &GetReceivedByAddressCmd{
		Address: address,
		MinConf: minConf,
	}
}

// GetTransactionCmd defines the gettransaction JSON-RPC command.
type GetTransactionCmd struct {
	Txid             string
	IncludeWatchOnly *bool `jsonrpcdefault:"false"`
}

// NewGetTransactionCmd returns a new instance which can be used to issue a
// gettransaction JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewGetTransactionCmd(txHash string, includeWatchOnly *bool) *GetTransactionCmd {
	return &GetTransactionCmd{
		Txid:             txHash,
		IncludeWatchOnly: includeWatchOnly,
	}
}

// GetWalletInfoCmd defines the getwalletinfo JSON-RPC command.
type GetWalletInfoCmd struct{}

// NewGetWalletInfoCmd returns a new instance which can be used to issue a
// getwalletinfo JSON-RPC command.
func NewGetWalletInfoCmd() *GetWalletInfoCmd {
	return &GetWalletInfoCmd{}
}

// ImportPrivKeyCmd defines the importprivkey JSON-RPC command.
type ImportPrivKeyCmd struct {
	PrivKey string
	Label   *string
	Rescan  *bool `jsonrpcdefault:"true"`
}

// NewImportPrivKeyCmd returns a new instance which can be used to issue a
// importprivkey JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewImportPrivKeyCmd(privKey string, label *string, rescan *bool) *ImportPrivKeyCmd {
	return &ImportPrivKeyCmd{
		PrivKey: privKey,
		Label:   label,
		Rescan:  rescan,
	}
}

// KeyPoolRefillCmd defines the keypoolrefill JSON-RPC command.
type KeyPoolRefillCmd struct {
	NewSize *uint `jsonrpcdefault:"100"`
}

// NewKeyPoolRefillCmd returns a new instance which can be used to issue a
// keypoolrefill JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewKeyPoolRefillCmd(newSize *uint) *KeyPoolRefillCmd {
	return &KeyPoolRefillCmd{
		NewSize: newSize,
	}
}

// ListAccountsCmd defines the listaccounts JSON-RPC command.
type ListAccountsCmd struct {
	MinConf *int `jsonrpcdefault:"1"`
}

// NewListAccountsCmd returns a new instance which can be used to issue a
// listaccounts JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewListAccountsCmd(minConf *int) *ListAccountsCmd {
	return &ListAccountsCmd{
		MinConf: minConf,
	}
}

// ListAddressGroupingsCmd defines the listaddressgroupings JSON-RPC command.
type ListAddressGroupingsCmd struct{}

// NewListAddressGroupingsCmd returns a new instance which can be used to issue
// a listaddressgroupoings JSON-RPC command.
func NewListAddressGroupingsCmd() *ListAddressGroupingsCmd {
	return &ListAddressGroupingsCmd{}
}

// ListLockUnspentCmd defines the listlockunspent JSON-RPC command.
type ListLockUnspentCmd struct{}

// NewListLockUnspentCmd returns a new instance which can be used to issue a
// listlockunspent JSON-RPC command.
func NewListLockUnspentCmd() *ListLockUnspentCmd {
	return &ListLockUnspentCmd{}
}

// ListReceivedByAccountCmd defines the listreceivedbyaccount JSON-RPC command.
type ListReceivedByAccountCmd struct {
	MinConf          *int  `jsonrpcdefault:"1"`
	IncludeEmpty     *bool `jsonrpcdefault:"false"`
	IncludeWatchOnly *bool `jsonrpcdefault:"false"`
}

// NewListReceivedByAccountCmd returns a new instance which can be used to issue
// a listreceivedbyaccount JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewListReceivedByAccountCmd(minConf *int, includeEmpty, includeWatchOnly *bool) *ListReceivedByAccountCmd {
	return &ListReceivedByAccountCmd{
		MinConf:          minConf,
		IncludeEmpty:     includeEmpty,
		IncludeWatchOnly: includeWatchOnly,
	}
}

// ListReceivedByAddressCmd defines the listreceivedbyaddress JSON-RPC command.
type ListReceivedByAddressCmd struct {
	MinConf          *int  `jsonrpcdefault:"1"`
	IncludeEmpty     *bool `jsonrpcdefault:"false"`
	IncludeWatchOnly *bool `jsonrpcdefault:"false"`
}

// NewListReceivedByAddressCmd returns a new instance which can be used to issue
// a listreceivedbyaddress JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewListReceivedByAddressCmd(minConf *int, includeEmpty, includeWatchOnly *bool) *ListReceivedByAddressCmd {
	return &ListReceivedByAddressCmd{
		MinConf:          minConf,
		IncludeEmpty:     includeEmpty,
		IncludeWatchOnly: includeWatchOnly,
	}
}

// ListSinceBlockCmd defines the listsinceblock JSON-RPC command.
type ListSinceBlockCmd struct {
	BlockHash           *string
	TargetConfirmations *int  `jsonrpcdefault:"1"`
	IncludeWatchOnly    *bool `jsonrpcdefault:"false"`
}

// NewListSinceBlockCmd returns a new instance which can be used to issue a
// listsinceblock JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewListSinceBlockCmd(blockHash *string, targetConfirms *int, includeWatchOnly *bool) *ListSinceBlockCmd {
	return &ListSinceBlockCmd{
		BlockHash:           blockHash,
		TargetConfirmations: targetConfirms,
		IncludeWatchOnly:    includeWatchOnly,
	}
}

// ListTransactionsCmd defines the listtransactions JSON-RPC command.
type ListTransactionsCmd struct {
	Account          *string
	Count            *int  `jsonrpcdefault:"10"`
	From             *int  `jsonrpcdefault:"0"`
	IncludeWatchOnly *bool `jsonrpcdefault:"false"`
}

// NewListTransactionsCmd returns a new instance which can be used to issue a
// listtransactions JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewListTransactionsCmd(account *string, count, from *int, includeWatchOnly *bool) *ListTransactionsCmd {
	return &ListTransactionsCmd{
		Account:          account,
		Count:            count,
		From:             from,
		IncludeWatchOnly: includeWatchOnly,
	}
}

// ListUnspentCmd defines the listunspent JSON-RPC command.
type ListUnspentCmd struct {
	MinConf   *int `jsonrpcdefault:"1"`
	MaxConf   *int `jsonrpcdefault:"9999999"`
	Addresses *[]string
}
type ListAllUnspentAbeCmd struct {
	Min *float64 `jsonrpcdefault:"0"`
	Max *float64 `jsonrpcdefault:"0"`
}

func NewListAllUnspentAbeCmd(min *float64, max *float64) *ListAllUnspentAbeCmd {
	return &ListAllUnspentAbeCmd{
		Min: min,
		Max: max,
	}
}

type ListUnmaturedAbeCmd struct {
	Min *float64 `jsonrpcdefault:"0"`
	Max *float64 `jsonrpcdefault:"0"`
}

func NewListUnmaturedAbeCmd(min *float64, max *float64) *ListUnmaturedAbeCmd {
	return &ListUnmaturedAbeCmd{
		Min: min,
		Max: max,
	}
}

type ListUnspentAbeCmd struct {
	Min *float64 `jsonrpcdefault:"0"`
	Max *float64 `jsonrpcdefault:"0"`
}

func NewListUnspentAbeCmd(min *float64, max *float64) *ListUnspentAbeCmd {
	return &ListUnspentAbeCmd{
		Min: min,
		Max: max,
	}
}

type RangeSpendableUTXOAbeCmd struct {
	Min *float64 `jsonrpcdefault:"0"`
	Max *float64 `jsonrpcdefault:"0"`
}

func NewRangeUTXOAbeCmd(min *float64, max *float64) *RangeSpendableUTXOAbeCmd {
	return &RangeSpendableUTXOAbeCmd{
		Min: min,
		Max: max,
	}
}

type ListUnspentCoinbaseAbeCmd struct {
	HeightStart  *int64
	HeightEnd    *int64
	CoinbaseFlag *bool
}

func NewListUnspentCoinbaseAbeCmd() *ListUnspentCoinbaseAbeCmd {
	return &ListUnspentCoinbaseAbeCmd{}
}

type ListSpentButUnminedAbeCmd struct {
	Min *float64 `jsonrpcdefault:"0"`
	Max *float64 `jsonrpcdefault:"0"`
}

func NewListSpentButUnminedAbeCmd(min *float64, max *float64) *ListSpentButUnminedAbeCmd {
	return &ListSpentButUnminedAbeCmd{
		Min: min,
		Max: max,
	}
}

type ListSpentAndMinedAbeCmd struct {
	Min *float64 `jsonrpcdefault:"0"`
	Max *float64 `jsonrpcdefault:"0"`
}

func NewListSpentAndMinedAbeCmd(min *float64, max *float64) *ListSpentAndMinedAbeCmd {
	return &ListSpentAndMinedAbeCmd{
		Min: min,
		Max: max,
	}
}

type ListConfirmedTxsCmd struct {
	Verbose *int `jsonrpcdefault:"0"`
}

func NewListConfirmedTxsCmd(verbose *int) *ListConfirmedTxsCmd {
	return &ListConfirmedTxsCmd{
		Verbose: verbose,
	}
}

type ListUnconfirmedTxsCmd struct {
	Verbose *int `jsonrpcdefault:"0"`
}

func NewListUnconfirmedTxsCmd(verbose *int) *ListUnconfirmedTxsCmd {
	return &ListUnconfirmedTxsCmd{
		Verbose: verbose,
	}
}

type ListInvalidTxsCmd struct {
	Verbose *int `jsonrpcdefault:"0"`
}

func NewListInvalidTxsCmd(verbose *int) *ListInvalidTxsCmd {
	return &ListInvalidTxsCmd{
		Verbose: verbose,
	}
}

type TxStatusCmd struct {
	TxHash string
}

func NewTxStatusCmd(hash string) *TxStatusCmd {
	return &TxStatusCmd{
		TxHash: hash,
	}
}

// NewListUnspentCmd returns a new instance which can be used to issue a
// listunspent JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewListUnspentCmd(minConf, maxConf *int, addresses *[]string) *ListUnspentCmd {
	return &ListUnspentCmd{
		MinConf:   minConf,
		MaxConf:   maxConf,
		Addresses: addresses,
	}
}

// LockUnspentCmd defines the lockunspent JSON-RPC command.
type LockUnspentCmd struct {
	Unlock       bool
	Transactions []TransactionInput
}

// NewLockUnspentCmd returns a new instance which can be used to issue a
// lockunspent JSON-RPC command.
func NewLockUnspentCmd(unlock bool, transactions []TransactionInput) *LockUnspentCmd {
	return &LockUnspentCmd{
		Unlock:       unlock,
		Transactions: transactions,
	}
}

type GetTxHashFromReqeustCmd struct {
	RequestHashStr string
}

func NewGetTxHashFromReqeustCmd(requestHashStr string) *GetTxHashFromReqeustCmd {
	return &GetTxHashFromReqeustCmd{
		RequestHashStr: requestHashStr,
	}
}

// MoveCmd defines the move JSON-RPC command.
type MoveCmd struct {
	FromAccount string
	ToAccount   string
	Amount      float64 // In BTC
	MinConf     *int    `jsonrpcdefault:"1"`
	Comment     *string
}

// NewMoveCmd returns a new instance which can be used to issue a move JSON-RPC
// command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewMoveCmd(fromAccount, toAccount string, amount float64, minConf *int, comment *string) *MoveCmd {
	return &MoveCmd{
		FromAccount: fromAccount,
		ToAccount:   toAccount,
		Amount:      amount,
		MinConf:     minConf,
		Comment:     comment,
	}
}

// SendFromCmd defines the sendfrom JSON-RPC command.
type SendFromCmd struct {
	FromAccount string
	ToAddress   string
	Amount      float64 // In BTC
	MinConf     *int    `jsonrpcdefault:"1"`
	Comment     *string
	CommentTo   *string
}

// NewSendFromCmd returns a new instance which can be used to issue a sendfrom
// JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewSendFromCmd(fromAccount, toAddress string, amount float64, minConf *int, comment, commentTo *string) *SendFromCmd {
	return &SendFromCmd{
		FromAccount: fromAccount,
		ToAddress:   toAddress,
		Amount:      amount,
		MinConf:     minConf,
		Comment:     comment,
		CommentTo:   commentTo,
	}
}

// SendManyCmd defines the sendmany JSON-RPC command.
type SendManyCmd struct {
	FromAccount string
	Amounts     map[string]float64 `jsonrpcusage:"{\"address\":amount,...}"` // In BTC
	MinConf     *int               `jsonrpcdefault:"1"`
	Comment     *string
}

// NewSendManyCmd returns a new instance which can be used to issue a sendmany
// JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewSendManyCmd(fromAccount string, amounts map[string]float64, minConf *int, comment *string) *SendManyCmd {
	return &SendManyCmd{
		FromAccount: fromAccount,
		Amounts:     amounts,
		MinConf:     minConf,
		Comment:     comment,
	}
}

type Pair struct {
	Address string  `json:"address"`
	Amount  float64 `json:"amount"`
}
type SendToAddressAbeCmd struct {
	Amounts            []Pair
	MinConf            *int     `jsonrpcdefault:"1"` //TODO(abe) what is the minconf used for?
	ScaleToFeeSatPerKb *float64 `jsonrpcdefault:"1"` // todo(AliceBob): <= 0 means that will use 'FeeSpecified'
	FeeSpecified       *float64 `jsonrpcdefault:"0"` //	todo(AliceBob): valid only if 'ScaleToFeeSatPerKb<=0' && 'FeeSpecified>0'
	UTXOSpecified      *string
	Comment            *string
}

func NewSendToAddressAbeCmd(amounts []Pair, minconf *int, scaleToFeeSatPerKb *float64, feeSpecified *float64, UTXOSpecified *string, comment *string) *SendToAddressAbeCmd {
	return &SendToAddressAbeCmd{
		Amounts:            amounts,
		MinConf:            minconf,
		ScaleToFeeSatPerKb: scaleToFeeSatPerKb,
		FeeSpecified:       feeSpecified,
		UTXOSpecified:      UTXOSpecified,
		Comment:            comment,
	}
}

type SendToPayeesCmd struct {
	Amounts            map[string]float64 `jsonrpcusage:"{\"name\":amount,...}"` // In BTC
	MinConf            *int               `jsonrpcdefault:"1"`                   //TODO(abe) what is the minconf used for?
	ScaleToFeeSatPerKb *float64           `jsonrpcdefault:"1"`                   // todo(AliceBob): <= 0 means that will use 'FeeSpecified'
	FeeSpecified       *float64           `jsonrpcdefault:"0"`                   //	todo(AliceBob): valid only if 'ScaleToFeeSatPerKb<=0' && 'FeeSpecified>0'
	UTXOSpecified      *string
	Comment            *string
}

func NewSendToPayeesCmd(amounts map[string]float64, minconf *int, scaleToFeeSatPerKb *float64, feeSpecified *float64, UTXOSpecified *string, comment *string) *SendToPayeesCmd {
	return &SendToPayeesCmd{
		Amounts:            amounts,
		MinConf:            minconf,
		ScaleToFeeSatPerKb: scaleToFeeSatPerKb,
		FeeSpecified:       feeSpecified,
		UTXOSpecified:      UTXOSpecified,
		Comment:            comment,
	}
}

// SendToAddressCmd defines the sendtoaddress JSON-RPC command.
type SendToAddressCmd struct {
	Address   string
	Amount    float64
	Comment   *string
	CommentTo *string
}

// NewSendToAddressCmd returns a new instance which can be used to issue a
// sendtoaddress JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewSendToAddressCmd(address string, amount float64, comment, commentTo *string) *SendToAddressCmd {
	return &SendToAddressCmd{
		Address:   address,
		Amount:    amount,
		Comment:   comment,
		CommentTo: commentTo,
	}
}

// SetAccountCmd defines the setaccount JSON-RPC command.
type SetAccountCmd struct {
	Address string
	Account string
}

// NewSetAccountCmd returns a new instance which can be used to issue a
// setaccount JSON-RPC command.
func NewSetAccountCmd(address, account string) *SetAccountCmd {
	return &SetAccountCmd{
		Address: address,
		Account: account,
	}
}

// SetTxFeeCmd defines the settxfee JSON-RPC command.
type SetTxFeeCmd struct {
	Amount float64 // In BTC
}

// NewSetTxFeeCmd returns a new instance which can be used to issue a settxfee
// JSON-RPC command.
func NewSetTxFeeCmd(amount float64) *SetTxFeeCmd {
	return &SetTxFeeCmd{
		Amount: amount,
	}
}

// SignMessageCmd defines the signmessage JSON-RPC command.
type SignMessageCmd struct {
	Address string
	Message string
}

// NewSignMessageCmd returns a new instance which can be used to issue a
// signmessage JSON-RPC command.
func NewSignMessageCmd(address, message string) *SignMessageCmd {
	return &SignMessageCmd{
		Address: address,
		Message: message,
	}
}

// RawTxInput models the data needed for raw transaction input that is used in
// the SignRawTransactionCmd struct.
type RawTxInput struct {
	Txid         string `json:"txid"`
	Vout         uint32 `json:"vout"`
	ScriptPubKey string `json:"scriptPubKey"`
	RedeemScript string `json:"redeemScript"`
}

// SignRawTransactionCmd defines the signrawtransaction JSON-RPC command.
type SignRawTransactionCmd struct {
	RawTx    string
	Inputs   *[]RawTxInput
	PrivKeys *[]string
	Flags    *string `jsonrpcdefault:"\"ALL\""`
}

// NewSignRawTransactionCmd returns a new instance which can be used to issue a
// signrawtransaction JSON-RPC command.
//
// The parameters which are pointers indicate they are optional.  Passing nil
// for optional parameters will use the default value.
func NewSignRawTransactionCmd(hexEncodedTx string, inputs *[]RawTxInput, privKeys *[]string, flags *string) *SignRawTransactionCmd {
	return &SignRawTransactionCmd{
		RawTx:    hexEncodedTx,
		Inputs:   inputs,
		PrivKeys: privKeys,
		Flags:    flags,
	}
}

// WalletLockCmd defines the walletlock JSON-RPC command.
type WalletLockCmd struct{}

// NewWalletLockCmd returns a new instance which can be used to issue a
// walletlock JSON-RPC command.
func NewWalletLockCmd() *WalletLockCmd {
	return &WalletLockCmd{}
}

// WalletPassphraseCmd defines the walletpassphrase JSON-RPC command.
type WalletPassphraseCmd struct {
	Passphrase string
	Timeout    int64
}

// NewWalletPassphraseCmd returns a new instance which can be used to issue a
// walletpassphrase JSON-RPC command.
func NewWalletPassphraseCmd(passphrase string, timeout int64) *WalletPassphraseCmd {
	return &WalletPassphraseCmd{
		Passphrase: passphrase,
		Timeout:    timeout,
	}
}

// FreshenCmd defines the walletpassphrase JSON-RPC command.
type FreshenCmd struct {
}

// Freshen returns a new instance which can be used to issue a
// walletpassphrase JSON-RPC command.
func Freshen(passphrase string) *FreshenCmd {
	return &FreshenCmd{}
}

// WalletPassphraseChangeCmd defines the walletpassphrase JSON-RPC command.
type WalletPassphraseChangeCmd struct {
	OldPassphrase string
	NewPassphrase string
}

// NewWalletPassphraseChangeCmd returns a new instance which can be used to
// issue a walletpassphrasechange JSON-RPC command.
func NewWalletPassphraseChangeCmd(oldPassphrase, newPassphrase string) *WalletPassphraseChangeCmd {
	return &WalletPassphraseChangeCmd{
		OldPassphrase: oldPassphrase,
		NewPassphrase: newPassphrase,
	}
}

func init() {
	// The commands in this file are only usable with a wallet server.
	flags := UFWalletOnly

	//MustRegisterCmd("addpayee", (*AddPayeeCmd)(nil), flags)
	//MustRegisterCmd("addmultisigaddress", (*AddMultisigAddressCmd)(nil), flags)
	//MustRegisterCmd("addwitnessaddress", (*AddWitnessAddressCmd)(nil), flags)
	//MustRegisterCmd("createmultisig", (*CreateMultisigCmd)(nil), flags)
	//MustRegisterCmd("dumpprivkey", (*DumpPrivKeyCmd)(nil), flags)
	//MustRegisterCmd("encryptwallet", (*EncryptWalletCmd)(nil), flags)
	MustRegisterCmd("estimatesmartfee", (*EstimateSmartFeeCmd)(nil), flags)
	MustRegisterCmd("estimatefee", (*EstimateFeeCmd)(nil), flags)
	MustRegisterCmd("estimatepriority", (*EstimatePriorityCmd)(nil), flags)
	//MustRegisterCmd("getaccount", (*GetAccountCmd)(nil), flags)
	//MustRegisterCmd("getaccountaddress", (*GetAccountAddressCmd)(nil), flags)
	//MustRegisterCmd("getaddressesbyaccount", (*GetAddressesByAccountCmd)(nil), flags)
	//MustRegisterCmd("getbalance", (*GetBalanceCmd)(nil), flags)
	//MustRegisterCmd("getbalances", (*GetBalancesCmd)(nil), flags)
	MustRegisterCmd("getbalancesabe", (*GetBalancesAbeCmd)(nil), flags)
	MustRegisterCmd("getdetailedutxos", (*GetDetailedUtxosCmd)(nil), flags)
	//MustRegisterCmd("getnewaddress", (*GetNewAddressCmd)(nil), flags)
	//MustRegisterCmd("getrawchangeaddress", (*GetRawChangeAddressCmd)(nil), flags)
	//MustRegisterCmd("getreceivedbyaccount", (*GetReceivedByAccountCmd)(nil), flags)
	//MustRegisterCmd("getreceivedbyaddress", (*GetReceivedByAddressCmd)(nil), flags)
	//MustRegisterCmd("gettransaction", (*GetTransactionCmd)(nil), flags)
	MustRegisterCmd("getwalletinfo", (*GetWalletInfoCmd)(nil), flags)
	//MustRegisterCmd("importprivkey", (*ImportPrivKeyCmd)(nil), flags)
	MustRegisterCmd("keypoolrefill", (*KeyPoolRefillCmd)(nil), flags) // TODO review it in btcwallet
	//MustRegisterCmd("listaccounts", (*ListAccountsCmd)(nil), flags)
	//MustRegisterCmd("listaddressgroupings", (*ListAddressGroupingsCmd)(nil), flags)
	MustRegisterCmd("listlockunspent", (*ListLockUnspentCmd)(nil), flags)
	//MustRegisterCmd("listreceivedbyaccount", (*ListReceivedByAccountCmd)(nil), flags)
	//MustRegisterCmd("listreceivedbyaddress", (*ListReceivedByAddressCmd)(nil), flags)
	MustRegisterCmd("listsinceblock", (*ListSinceBlockCmd)(nil), flags)
	//MustRegisterCmd("listtransactions", (*ListTransactionsCmd)(nil), flags)
	//MustRegisterCmd("listunspent", (*ListUnspentCmd)(nil), flags)
	MustRegisterCmd("listallutxoabe", (*ListAllUnspentAbeCmd)(nil), flags)
	MustRegisterCmd("listimmaturetxoabe", (*ListUnmaturedAbeCmd)(nil), flags)
	MustRegisterCmd("listmaturetxoabe", (*ListUnspentAbeCmd)(nil), flags)
	MustRegisterCmd("listmaturecoinbasetxoabe", (*ListUnspentCoinbaseAbeCmd)(nil), flags)
	MustRegisterCmd("listunconfirmedtxoabe", (*ListSpentButUnminedAbeCmd)(nil), flags)
	MustRegisterCmd("listconfirmedtxoabe", (*ListSpentAndMinedAbeCmd)(nil), flags)

	MustRegisterCmd("rangespendableutxo", (*RangeSpendableUTXOAbeCmd)(nil), flags)

	MustRegisterCmd("listconfirmedtxs", (*ListConfirmedTxsCmd)(nil), flags)
	MustRegisterCmd("listunconfirmedtxs", (*ListUnconfirmedTxsCmd)(nil), flags)
	MustRegisterCmd("listinvalidtxs", (*ListInvalidTxsCmd)(nil), flags)
	MustRegisterCmd("transactionstatus", (*TxStatusCmd)(nil), flags)
	MustRegisterCmd("lockunspent", (*LockUnspentCmd)(nil), flags)
	MustRegisterCmd("gettxhashfromreqeust", (*GetTxHashFromReqeustCmd)(nil), flags)
	MustRegisterCmd("move", (*MoveCmd)(nil), flags) // TODO
	//MustRegisterCmd("sendfrom", (*SendFromCmd)(nil), flags)
	//MustRegisterCmd("sendmany", (*SendManyCmd)(nil), flags)
	MustRegisterCmd("sendtoaddressesabe", (*SendToAddressAbeCmd)(nil), flags)
	MustRegisterCmd("generateaddressabe", (*GenerateAddressCmd)(nil), flags)
	MustRegisterCmd("listfreeaddresses", (*ListFreeAddressesCmd)(nil), flags)
	MustRegisterCmd("addressmaxsequencenumber", (*AddressMaxSequenceNumberCmd)(nil), flags)
	MustRegisterCmd("addressrange", (*AddressRangeCmd)(nil), flags)
	//MustRegisterCmd("sendtoaddress", (*SendToAddressCmd)(nil), flags)
	//MustRegisterCmd("sendtopayee", (*SendToPayeesCmd)(nil), flags)
	//MustRegisterCmd("setaccount", (*SetAccountCmd)(nil), flags)
	MustRegisterCmd("settxfee", (*SetTxFeeCmd)(nil), flags)       // TODO
	MustRegisterCmd("signmessage", (*SignMessageCmd)(nil), flags) // TODO
	MustRegisterCmd("signrawtransaction", (*SignRawTransactionCmd)(nil), flags)
	MustRegisterCmd("walletlock", (*WalletLockCmd)(nil), flags)
	MustRegisterCmd("walletunlock", (*WalletPassphraseCmd)(nil), flags)
	//MustRegisterCmd("freshen", (*FreshenCmd)(nil), flags)
	MustRegisterCmd("walletpassphrasechange", (*WalletPassphraseChangeCmd)(nil), flags)
}
