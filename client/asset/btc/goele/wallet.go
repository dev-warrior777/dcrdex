package goele

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/dev-warrior777/go-electrum-client/client"
	"github.com/dev-warrior777/go-electrum-client/client/btc"
	"github.com/dev-warrior777/go-electrum-client/electrumx"
	"github.com/dev-warrior777/go-electrum-client/wallet"
)

// const defaultWalletTimeout = 10 * time.Second

var (
	coins = []string{"btc"} // add as implemented
)

// WalletClient is a Goele wallet library client.
type WalletClient struct {
	coin string
	net  *chaincfg.Params
	pw   string
	ec   client.ElectrumClient
}

// NewWalletClient constructs a new Goele wallet library client.
func NewWalletClient(
	coin string,
	net *chaincfg.Params,
	pw string /*, more cfg */) (WalletClient, error) {

	gc, err := makeBasicClient(coin, net)
	if err != nil {
		return WalletClient{}, err
	}
	return WalletClient{
		coin: coin,
		net:  net,
		pw:   pw,
		ec:   gc,
	}, nil
}

func makeBasicClient(coin string, net *chaincfg.Params) (client.ElectrumClient, error) {
	contains := func(s []string, str string) bool {
		for _, v := range s {
			if v == str {
				return true
			}
		}
		return false
	}
	if !contains(coins, coin) {
		return nil, errors.New("invalid coin")
	}

	cfg := client.NewDefaultConfig()
	appDir, err := client.GetConfigPath()
	if err != nil {
		return nil, err
	}
	coinNetDir := filepath.Join(appDir, coin, net.Name)
	err = os.MkdirAll(coinNetDir, os.ModeDir|0777)
	if err != nil {
		return nil, err
	}
	cfg.DataDir = coinNetDir

	switch coin {
	case "btc":
		cfg.Chain = wallet.Bitcoin
		switch net {
		case &chaincfg.RegressionNetParams:
			cfg.Params = &chaincfg.RegressionNetParams
			cfg.TrustedPeer = electrumx.ServerAddr{
				Net: "ssl", Addr: "127.0.0.1:53002",
			}
			cfg.StoreEncSeed = true
			cfg.Testing = true
			cfg.DbType = "sqlite" // good for dev as you can see inside the db in real time

			return btc.NewBtcElectrumClient(cfg), nil
		case &chaincfg.TestNet3Params:
			cfg.Params = &chaincfg.TestNet3Params
			cfg.TrustedPeer = electrumx.ServerAddr{
				// in servers_testnet.json from electrum; so maybe more trustworthy
				// Net: "ssl", Addr: "testnet.aranguren.org:51002",
				// Net: "tcp", Addr: "testnet.aranguren.org:51001",
				// Net: "ssl", Addr: "blockstream.info:993", // fail GetTransaction (verbose)
				// Net: "tcp", Addr: "blockstream.info:143", // fail GetTransaction (verbise)
				// Net: "ssl", Addr: "electrum.blockstream.info:60002", // fail GetTransaction (verbose)
				// Net: "ssl", Addr: "testnet.hsmiths.com:53012", // down?
				// Net: "ssl", Addr: "blackie.c3-soft.com:57006", // down?
				// Net: "tcp", Addr: "blackie.c3-soft.com:57005", // down?
				// Net: "ssl", Addr: "testnet.qtornado.com:51002",// ok today
				Net: "tcp", Addr: "testnet.qtornado.com:51001",
			}
			cfg.StoreEncSeed = true
			cfg.Testing = true
			return btc.NewBtcElectrumClient(cfg), nil
		case &chaincfg.MainNetParams:
			cfg.Params = &chaincfg.MainNetParams
			cfg.TrustedPeer = electrumx.ServerAddr{
				Net: "ssl", Addr: "elx.bitske.com:50002",
				// Net: "ssl", Addr: "blockstream.info:700", // fail GetTransaction (verbose)
			}
			cfg.StoreEncSeed = false
			cfg.Testing = false
			return btc.NewBtcElectrumClient(cfg), nil
		}
	}
	return nil, errors.New("invalid coin config")
}

// Start starts goele's electrumx node and sync's client headers chain.
// This context is the parent of the goele server's context and is shared
// with goele library functions.
func (wc *WalletClient) Start(ctx context.Context) error {
	return wc.ec.Start(ctx)
}

func (wc *WalletClient) LoadWallet(ctx context.Context) error {
	err := wc.ec.LoadWallet(wc.pw)
	if err != nil {
		return err
	}
	err = wc.ec.SyncWallet(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (wc *WalletClient) Tip() (int64, bool) {
	return wc.ec.Tip()
}

func (wc *WalletClient) GetBlockHeader(height int64) *wire.BlockHeader {
	return wc.ec.GetBlockHeader(height)
}

func (wc *WalletClient) GetBlockHeaders(startHeight, count int64) ([]*wire.BlockHeader, error) {
	return wc.ec.GetBlockHeaders(startHeight, count)
}

func (wc *WalletClient) RegisterTipChangeNotify() (<-chan int64, error) {
	return wc.ec.RegisterTipChangeNotify()
}

func (wc *WalletClient) UnregisterTipChangeNotify() {
	wc.ec.UnregisterTipChangeNotify()
}

func (wc *WalletClient) FeeRate(ctx context.Context, confTarget int64) (int64, error) {
	feeRate, err := wc.ec.FeeRate(ctx, confTarget)
	if err != nil {
		return 0, err
	}
	if feeRate == -1 { // no server estimate
		return 1000, nil
	}
	return feeRate, nil
}

// Own wallet

func (wc *WalletClient) GetUnusedAddress(ctx context.Context) (string, error) {
	return wc.ec.UnusedAddress(ctx)
}

func (wc *WalletClient) GetUnusedChangeAddress(ctx context.Context) (string, error) {
	return wc.ec.ChangeAddress(ctx)
}

func (wc *WalletClient) GetBalance() (*Balance, error) {
	confirmed, unconfirmed, locked, err := wc.ec.Balance()
	if err != nil {
		return nil, err
	}
	return &Balance{
		Confirmed:   float64(confirmed) / 1e8,   // >0 confirms
		Unconfirmed: float64(unconfirmed) / 1e8, // 0 confirms
		Immature:    float64(0),                 // always 0.0
		Locked:      float64(locked) / 1e8,      // the value of all locked goele utxos
	}, nil
}

func (wc *WalletClient) ListUnspent(onlySpendable bool) ([]*ListUnspent, error) {
	utxos, err := wc.ec.ListUnspent()
	if err != nil {
		return nil, err
	}
	var res = make([]*ListUnspent, 0, 16)
	for _, utxo := range utxos {
		// valid stored utxos are never <0
		if utxo.AtHeight < 0 {
			continue
		}
		// unconfirmed
		if onlySpendable && utxo.AtHeight == 0 {
			continue
		}
		// frozen
		if onlySpendable && utxo.Frozen {
			continue
		}
		amt := btcutil.Amount(utxo.Value)
		btcValue := amt.ToBTC()
		_, addresses, _, err := txscript.ExtractPkScriptAddrs(utxo.ScriptPubkey, wc.net)
		if err != nil {
			return nil, err
		}
		if len(addresses) != 1 {
			return nil, errors.New("ExtractPkScriptAddrs - too many addresses returned")
		}
		addr := addresses[0].String()

		listUnspentResult := &ListUnspent{
			Address:       addr,
			PkScript:      utxo.ScriptPubkey,
			Value:         btcValue,
			Height:        utxo.AtHeight,
			PrevOutHash:   utxo.Op.Hash.String(),
			PrevOutIdx:    utxo.Op.Index,
			RedeemScript:  "",
			WitnessScript: "",
			Frozen:        utxo.Frozen,
		}
		res = append(res, listUnspentResult)
	}
	return res, nil
}

func (wc *WalletClient) FreezeUTXO(txid string, vout uint32) error {
	return wc.ec.FreezeUTXO(txid, vout)
}

func (wc *WalletClient) UnfreezeUTXO(txid string, vout uint32) error {
	return wc.ec.UnfreezeUTXO(txid, vout)
}

func (wc *WalletClient) CheckAddress(addr string) (valid, mine bool, err error) {
	return wc.ec.ValidateAddress(addr)
}

func (wc *WalletClient) SignTx(txBytes []byte) ([]byte, error) {
	return wc.ec.SignTx(wc.pw, txBytes)
}

func (wc *WalletClient) GetPrivKeyForAddress(addr string) (string, error) {
	return wc.ec.GetPrivKeyForAddress(wc.pw, addr)
}

func (wc *WalletClient) GetWalletTx(txid string) (int, bool, []byte, error) {
	return wc.ec.GetWalletTx(txid)
}

func (wc *WalletClient) GetWalletSpents() ([]*Spent, error) {
	spents := make([]*Spent, 0, 16)
	stxos, err := wc.ec.GetWalletSpents()
	if err != nil {
		return nil, err
	}
	for _, stxo := range stxos {
		spent := &Spent{
			UtxoOp:           &stxo.Utxo.Op,
			UtxoAtHeight:     stxo.Utxo.AtHeight,
			UtxoValue:        stxo.Utxo.Value,
			UtxoScriptPubkey: stxo.Utxo.ScriptPubkey,
			SpendHeight:      stxo.SpendHeight,
			SpendTxid:        &stxo.SpendTxid,
		}
		spents = append(spents, spent)
	}
	return spents, nil
}

func (wc *WalletClient) Broadcast(ctx context.Context, rawTx []byte) (string, error) {
	return wc.ec.Broadcast(ctx, rawTx)
}

// Server pass thru

// Let's try and not use this! Some servers do not support verbose queries
//
// GetTransaction gets comprehensive info for a transaction on the network. It
// mutates the info into more useable types.
// TODO: see if we need the detailed pkscript data.
func (wc *WalletClient) GetTransaction(ctx context.Context, txid string) (*Transaction, error) {
	getTxRes, err := wc.ec.GetTransaction(ctx, txid)
	if err != nil {
		return nil, err
	}
	if txid != getTxRes.TxID {
		// general cheap fast sanity check
		return nil, fmt.Errorf("not the requested txid - have %s wanted %s", getTxRes.TxID, txid)
	}
	txBytes, err := hex.DecodeString(getTxRes.Hex)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(txBytes)
	msgTx := wire.NewMsgTx(wire.TxVersion)
	err = msgTx.Deserialize(buf)
	if err != nil {
		return nil, err
	}
	tx := &Transaction{
		TxID:      getTxRes.TxID,
		TxBytes:   txBytes,
		Tx:        msgTx,
		Version:   getTxRes.Version,
		Size:      getTxRes.Size,
		VSize:     getTxRes.VSize,
		Weight:    getTxRes.Weight,
		LockTime:  getTxRes.LockTime,
		BlockHash: getTxRes.BlockHash,
		// can be different from goele wallet client at client start up
		Confirmations: getTxRes.Confirmations,
		Time:          getTxRes.Time,
		BlockTime:     getTxRes.BlockTime,
	}
	return tx, nil
}

func (wc *WalletClient) GetRawTransaction(ctx context.Context, txid string) ([]byte, error) {
	return wc.ec.GetRawTransaction(ctx, txid)
}

func (wc *WalletClient) GetAddressHistory(ctx context.Context, addr string) ([]*AddressHistory, error) {
	history, err := wc.ec.GetAddressHistory(ctx, addr)
	if err != nil {
		return nil, err
	}
	var addressHistory = make([]*AddressHistory, 0)
	for _, h := range history {
		fee := int64(h.Fee)
		res := &AddressHistory{
			Height: h.Height,
			TxHash: h.TxHash,
			Fee:    &fee, // only mempool txs
		}
		addressHistory = append(addressHistory, res)
	}
	return addressHistory, nil
}

func (wc *WalletClient) GetAddressUnspent(ctx context.Context, addr string) ([]*AddressUnspent, error) {
	unspents, err := wc.ec.GetAddressUnspent(ctx, addr)
	if err != nil {
		return nil, err
	}
	var addressUnspent = make([]*AddressUnspent, 0)
	for _, u := range unspents {
		res := &AddressUnspent{
			Height: u.Height,
			TxHash: u.TxHash,
			TxPos:  int32(u.TxPos),
			Value:  u.Value,
		}
		addressUnspent = append(addressUnspent, res)
	}
	return addressUnspent, nil
}
