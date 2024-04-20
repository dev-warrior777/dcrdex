// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package btc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"decred.org/dcrdex/client/asset"
	"decred.org/dcrdex/client/asset/btc/goele"
	"decred.org/dcrdex/dex"
	dexbtc "decred.org/dcrdex/dex/networks/btc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type goeleWalletClient interface {
	Start(ctx context.Context) error
	LoadWallet(ctx context.Context) error
	Tip() (int64, bool)
	GetBlockHeader(height int64) *wire.BlockHeader
	GetBlockHeaders(startHeight, count int64) ([]*wire.BlockHeader, error)
	RegisterTipChangeNotify() (<-chan int64, error)
	UnregisterTipChangeNotify()

	FeeRate(ctx context.Context, confTarget int64) (int64, error)

	// wallet external
	Broadcast(ctx context.Context, rawTx []byte) (string, error)

	// wallet
	GetUnusedAddress(ctx context.Context) (string, error)
	GetUnusedChangeAddress(ctx context.Context) (string, error)
	GetBalance() (*goele.Balance, error)
	ListUnspent(onlySpendable bool) ([]*goele.ListUnspent, error)
	FreezeUTXO(txid string, vout uint32) error
	UnfreezeUTXO(txid string, vout uint32) error
	CheckAddress(addr string) (valid, mine bool, err error)
	SignTx(txBytes []byte) ([]byte, error)
	GetPrivKeyForAddress(addr string) (string, error)
	GetWalletTx(txid string) (int, bool, []byte, error)
	GetWalletSpents() ([]*goele.Spent, error) // not yet impl.

	//pass thru
	GetTransaction(ctx context.Context, txid string) (*goele.Transaction, error)
	GetRawTransaction(ctx context.Context, txid string) ([]byte, error)
	GetAddressHistory(ctx context.Context, addr string) ([]*goele.AddressHistory, error)
	GetAddressUnspent(ctx context.Context, addr string) ([]*goele.AddressUnspent, error)
}

type goeleWallet struct {
	log         dex.Logger
	chainParams *chaincfg.Params
	decodeAddr  dexbtc.AddressDecoder
	stringAddr  dexbtc.AddressStringer
	wallet      goeleWalletClient
	segwit      bool

	// ctx is set on connect, and used in asset.Wallet and btc.Wallet interface
	// method implementations that have no ctx arg yet (refactoring TODO).
	ctx context.Context

	lockedOutpointsMtx sync.RWMutex
	lockedOutpoints    map[OutPoint]struct{}

	pwMtx    sync.RWMutex
	pw       string
	unlocked bool
}

var ErrNoHeadersSync = errors.New("client headers not yet synced")

type goeleWalletConfig struct {
	params       *chaincfg.Params
	log          dex.Logger
	addrDecoder  dexbtc.AddressDecoder
	addrStringer dexbtc.AddressStringer
	segwit       bool // indicates if segwit addresses are expected from requests
	wc           goele.WalletClient
}

func newGoeleWallet(gwc goeleWalletClient, cfg *goeleWalletConfig) *goeleWallet {
	addrDecoder := cfg.addrDecoder
	if addrDecoder == nil {
		addrDecoder = btcutil.DecodeAddress
	}
	addrStringer := cfg.addrStringer
	if addrStringer == nil {
		addrStringer = func(addr btcutil.Address, _ *chaincfg.Params) (string, error) {
			return addr.String(), nil
		}
	}

	return &goeleWallet{
		log:         cfg.log,
		chainParams: cfg.params,
		decodeAddr:  addrDecoder,
		stringAddr:  addrStringer,
		segwit:      cfg.segwit,
		wallet:      gwc,
		// TODO: remove this when all interface methods are given a Context. In
		// the meantime, init with a valid sentry context until connect().
		ctx:             context.TODO(),
		lockedOutpoints: make(map[OutPoint]struct{}),
	}
}

// BEGIN unimplemented asset.Wallet methods

func (gw *goeleWallet) RawRequest(context.Context, string, []json.RawMessage) (json.RawMessage, error) {
	return nil, errors.New("not available") // and not used
}

// END unimplemented methods

// part of btc.Wallet interface
func (gw *goeleWallet) connect(ctx context.Context, wg *sync.WaitGroup) error {
	err := gw.wallet.Start(ctx)
	if err != nil {
		return err
	}
	err = gw.wallet.LoadWallet(ctx)
	if err != nil {
		return err
	}
	return err
}

// part of btc.Wallet interface
func (gw *goeleWallet) reconfigure(cfg *asset.WalletConfig, currentAddress string) (restartRequired bool, err error) {
	return true, errors.New("goeleWallet cannot reconfigure")
}

// part of btc.Wallet interface
func (gw *goeleWallet) sendRawTransaction(tx *wire.MsgTx) (*chainhash.Hash, error) {
	b, err := serializeMsgTx(tx)
	if err != nil {
		return nil, err
	}
	// // Add the transaction to the wallet DB before broadcasting it on the
	// // network, otherwise it is not immediately recorded. This is expected to
	// // error on non-wallet transactions such as counterparty transactions.
	// _, err = gw.wallet.AddLocalTx(b)
	// if err != nil && !strings.Contains(err.Error(), "unrelated to this wallet") {
	// 	gw.log.Warnf("Failed to add tx to the wallet DB: %v", err)
	// }
	txid, err := gw.wallet.Broadcast(gw.ctx, b)
	if err != nil {
		return nil, err
	}
	hash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return nil, err // well that sucks, it's already sent
	}
	ops := make([]*Output, len(tx.TxIn))
	for i, txIn := range tx.TxIn {
		prevOut := txIn.PreviousOutPoint
		ops[i] = &Output{Pt: NewOutPoint(&prevOut.Hash, prevOut.Index)}
	}
	if err = gw.lockUnspent(true, ops); err != nil {
		gw.log.Errorf("Failed to unlock spent UTXOs: %v", err)
	}
	return hash, nil
}

func (gw *goeleWallet) outputIsSpent(ctx context.Context, txHash *chainhash.Hash, vout uint32, pkScript []byte) (bool, error) {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, gw.chainParams)
	if err != nil {
		return false, fmt.Errorf("failed to decode pkScript: %w", err)
	}
	if len(addrs) != 1 {
		return false, fmt.Errorf("pkScript encodes %d addresses, not 1", len(addrs))
	}
	addr, err := gw.stringAddr(addrs[0], gw.chainParams)
	if err != nil {
		return false, fmt.Errorf("invalid address encoding: %w", err)
	}
	// Now see if the unspent outputs for this address include this outpoint.
	addrUnspents, err := gw.wallet.GetAddressUnspent(ctx, addr)
	if err != nil {
		return false, fmt.Errorf("getaddressunspent: %w", err)
	}
	txid := txHash.String()
	for _, utxo := range addrUnspents {
		if utxo.TxHash == txid && uint32(utxo.TxPos) == vout {
			return false, nil // still unspent
		}
	}
	gw.log.Infof("Output %s:%d not found in unspent output list. Searching for spending txn...",
		txid, vout)
	// getaddressunspent can sometimes exclude an unspent output if it is new,
	// so now search for an actual spending txn, which is a more expensive
	// operation so we only fall back on this.
	spendTx, _, err := gw.findOutputSpender(ctx, txHash, vout)
	if err != nil {
		return false, fmt.Errorf("failure while checking for spending txn: %v", err)
	}
	return spendTx != nil, nil
}

// part of btc.Wallet interface
func (gw *goeleWallet) getTxOut(txHash *chainhash.Hash, vout uint32, _ []byte, _ time.Time) (*wire.TxOut, uint32, error) {
	return gw.getTxOutput(gw.ctx, txHash, vout)
}

func (gw *goeleWallet) getTxOutput(ctx context.Context, txHash *chainhash.Hash, vout uint32) (*wire.TxOut, uint32, error) {
	// In case this is a wallet transaction, try the wallet DB methods first,
	// then fall back to the more expensive server request.
	txid := txHash.String()
	txRaw, confs, err := gw.checkWalletTx(txid)
	if err != nil {
		txRes, err := gw.wallet.GetTransaction(ctx, txid)
		if err != nil {
			return nil, 0, err
		}
		confs = uint32(txRes.Confirmations)
		txRaw = txRes.TxBytes
	}

	msgTx, err := msgTxFromBytes(txRaw)
	if err != nil {
		return nil, 0, err
	}
	if vout >= uint32(len(msgTx.TxOut)) {
		return nil, 0, fmt.Errorf("output %d of tx %v does not exists", vout, txid)
	}
	pkScript := msgTx.TxOut[vout].PkScript
	amt := msgTx.TxOut[vout].Value

	// Given the pkScript, we can query for unspent outputs to see if this one
	// is unspent.
	spent, err := gw.outputIsSpent(ctx, txHash, vout, pkScript)
	if err != nil {
		return nil, 0, err
	}
	if spent {
		return nil, 0, nil
	}

	return wire.NewTxOut(amt, pkScript), confs, nil
}

func (gw *goeleWallet) getBlockHeaderByHeight(height int64) *wire.BlockHeader {
	return gw.wallet.GetBlockHeader(height)
}

// part of btc.Wallet interface
func (gw *goeleWallet) medianTime() (time.Time, error) {
	chainHeight, err := gw.getBestBlockHeight()
	if err != nil {
		return time.Time{}, err
	}
	return gw.calcMedianTime(int64(chainHeight))
}

func (gw *goeleWallet) calcMedianTime(height int64) (time.Time, error) {
	startHeight := height - medianTimeBlocks + 1
	if startHeight < 0 {
		startHeight = 0
	}
	// TODO: check a block hash => median time cache
	hdrs, err := gw.wallet.GetBlockHeaders(startHeight, height-startHeight+1)
	if err != nil {
		return time.Time{}, err
	}
	blkCount := len(hdrs)
	if blkCount != medianTimeBlocks {
		gw.log.Warnf("Failed to retrieve headers for %d blocks since block %v, got %d",
			medianTimeBlocks, height, blkCount)
	}

	timestamps := make([]int64, 0, blkCount)
	for _, hdr := range hdrs {
		timestamps = append(timestamps, hdr.Timestamp.Unix())
	}

	sort.Slice(timestamps, func(i, j int) bool {
		return timestamps[i] < timestamps[j]
	})

	medianTimestamp := timestamps[len(timestamps)/2]
	return time.Unix(medianTimestamp, 0), nil
}

// part of btc.Wallet interface
func (gw *goeleWallet) getBlockHash(height int64) (*chainhash.Hash, error) {
	hdr := gw.getBlockHeaderByHeight(height)
	hash := hdr.BlockHash()
	return &hash, nil
}

// part of btc.Wallet interface
func (gw *goeleWallet) getBestBlockHash() (*chainhash.Hash, error) {
	height, synced := gw.wallet.Tip()
	if !synced {
		return nil, ErrNoHeadersSync
	}
	return gw.getBlockHash(height)
}

// part of btc.Wallet interface
func (gw *goeleWallet) getBestBlockHeight() (int32, error) {
	height, synced := gw.wallet.Tip()
	if !synced {
		return 0, ErrNoHeadersSync
	}
	return int32(height), nil
}

// part of btc.Wallet interface
func (gw *goeleWallet) getBestBlockHeader() (*BlockHeader, error) {
	height, synced := gw.wallet.Tip()
	if !synced {
		return nil, ErrNoHeadersSync
	}
	hdr := gw.wallet.GetBlockHeader(height)

	header := &BlockHeader{
		Hash:              hdr.BlockHash().String(),
		Height:            height,
		Confirmations:     1, // it's the head
		Time:              hdr.Timestamp.Unix(),
		PreviousBlockHash: hdr.PrevBlock.String(),
	}
	return header, nil
}

// part of btc.Wallet interface
func (gw *goeleWallet) balances() (*GetBalancesResult, error) {
	gBal, err := gw.wallet.GetBalance()
	if err != nil {
		return nil, err
	}
	// Electrum NOTE: "Nothing from the Electrum wallet's response indicates trusted vs.
	// untrusted. To allow unconfirmed coins to be spent, we treat both
	// confirmed and unconfirmed as trusted. This is like dogecoind's handling
	// of balance"
	// TODO: listunspent -> checkWalletTx(txid) -> for each input, checkWalletTx(prevout)
	// and ismine(addr)
	//
	// Goele is a simpler wallet than electrum (which for example moves the gap limit
	// only after 3 confs and has a 'thread' doing that)
	// For goele 0 confirms means unmined and >0 confirms means spendable if not locked.
	// Goele also does not yet implement watch only fully (yet?)
	return &GetBalancesResult{
		Mine: Balances{
			Trusted:  gBal.Confirmed,
			Immature: float64(0),
		},
	}, nil
}

// part of btc.Wallet interface
func (gw *goeleWallet) listUnspent() ([]*ListUnspentResult, error) {
	// get spendable utxos
	eUnspent, err := gw.wallet.ListUnspent(true)
	if err != nil {
		return nil, err
	}

	// TODO: test remove some of below logic

	height32, err := gw.getBestBlockHeight()
	if err != nil {
		return nil, err
	}
	chainHeight := int64(height32)
	// Filter out locked outpoints since listUnspent includes them.
	lockedOPs := gw.listLockedOutpoints()
	lockedOPMap := make(map[RPCOutpoint]bool, len(lockedOPs))
	for _, pt := range lockedOPs {
		lockedOPMap[*pt] = true
	}

	unspents := make([]*ListUnspentResult, 0, len(eUnspent))
	for _, utxo := range eUnspent {
		if lockedOPMap[RPCOutpoint{utxo.PrevOutHash, utxo.PrevOutIdx}] {
			continue
		}
		var confs uint32
		if height := utxo.Height; height > 0 {
			// height is non-zero, so confirmed, but if the RPCs are
			// inconsistent with respect to height, avoid an underflow or
			// appearing unconfirmed.
			//
			// Goele receives unreliable new header notifications on first startup
			// for 2 blocks, after that is reliable  within a few seconds.
			// Goele utxos AtHeight > 0 are considered confirmed. They may be
			// locked == frozen though. checkout: goele/wallet.go
			if height > chainHeight {
				confs = 1
			} else {
				confs = uint32(chainHeight - height + 1)
			}
		}
		redeemScript, err := hex.DecodeString(utxo.RedeemScript)
		if err != nil {
			gw.log.Warnf("Output (%v:%d) with bad redeemscript %v found: %v",
				utxo.PrevOutHash, utxo.PrevOutIdx, utxo.RedeemScript, err)
			continue
		}

		unspents = append(unspents, &ListUnspentResult{
			TxID:          utxo.PrevOutHash,
			Vout:          utxo.PrevOutIdx,
			Address:       utxo.Address,
			ScriptPubKey:  utxo.PkScript,
			Amount:        utxo.Value,
			Confirmations: confs,
			RedeemScript:  redeemScript,
			Spendable:     true, // can electrum have unspendable?, goele listunspent(onlySpendable)
			Solvable:      true,
			// Safe is unknown, leave ptr nil
		})
	}
	return unspents, nil
}

func (gw *goeleWallet) unlockAll() error {
	// get all utxos, spendable or not
	walletUnspents, err := gw.wallet.ListUnspent(false)
	if err != nil {
		return err
	}
	// unfreeze all frozen
	for _, u := range walletUnspents {
		if u.Frozen {
			gw.wallet.UnfreezeUTXO(u.PrevOutHash, u.PrevOutIdx)
		}
	}
	return nil
}

// part of btc.Wallet interface
func (gw *goeleWallet) lockUnspent(unlock bool, ops []*Output) error {
	// fmt.Printf("lockUnspent(%v, %v)\n", unlock, ops)
	if unlock && ops == nil {
		// we are coming in from the 'special case' ReturnCoins(nil) which
		// unlocks all locked outpoints. If that logic changes then change
		// this also maybe.
		return gw.unlockAll()
	}
	// get all utxos, spendable or not
	eUnspent, err := gw.wallet.ListUnspent(false)
	if err != nil {
		return err
	}
	opMap := make(map[OutPoint]struct{}, len(ops))
	for _, op := range ops {
		opMap[op.Pt] = struct{}{}
	}
	// For the ones that appear in listunspent, use (un)freeze_utxo also.
unspents:
	for _, utxo := range eUnspent {
		for op := range opMap {
			if op.Vout == utxo.PrevOutIdx && op.TxHash.String() == utxo.PrevOutHash {
				// FreezeUTXO and UnfreezeUTXO do not error when called
				// repeatedly for the same UTXO.
				if unlock {
					if err = gw.wallet.UnfreezeUTXO(utxo.PrevOutHash, utxo.PrevOutIdx); err != nil {
						gw.log.Warnf("UnfreezeUTXO(%s:%d) failed: %v", utxo.PrevOutHash, utxo.PrevOutIdx, err)
						// Maybe we lost a race somewhere. Keep going.
					}
					gw.lockedOutpointsMtx.Lock()
					delete(gw.lockedOutpoints, op)
					gw.lockedOutpointsMtx.Unlock()
					delete(opMap, op)
					continue unspents
				}
				// lock
				if err = gw.wallet.FreezeUTXO(utxo.PrevOutHash, utxo.PrevOutIdx); err != nil {
					gw.log.Warnf("FreezeUTXO(%s:%d) failed: %v", utxo.PrevOutHash, utxo.PrevOutIdx, err)
				}
				// listunspent returns locked utxos, so we have to track it.
				gw.lockedOutpointsMtx.Lock()
				gw.lockedOutpoints[op] = struct{}{}
				gw.lockedOutpointsMtx.Unlock()
				delete(opMap, op)
				continue unspents
			}
		}
	}

	// If not in the listunspent response, fail if trying to lock, otherwise
	// just remove them from the lockedOutpoints map (unlocking spent UTXOs).
	if len(opMap) > 0 && !unlock {
		return fmt.Errorf("failed to lock some utxos")
	}
	for op := range opMap {
		gw.lockedOutpointsMtx.Lock()
		delete(gw.lockedOutpoints, op)
		gw.lockedOutpointsMtx.Unlock()
	}

	return nil
}

func (gw *goeleWallet) listLockedOutpoints() []*RPCOutpoint {
	gw.lockedOutpointsMtx.RLock()
	defer gw.lockedOutpointsMtx.RUnlock()
	locked := make([]*RPCOutpoint, 0, len(gw.lockedOutpoints))
	for op := range gw.lockedOutpoints {
		locked = append(locked, &RPCOutpoint{
			TxID: op.TxHash.String(),
			Vout: op.Vout,
		})
	}
	return locked
}

// part of btc.Wallet interface
func (gw *goeleWallet) listLockUnspent() ([]*RPCOutpoint, error) {
	return gw.listLockedOutpoints(), nil
}

// externalAddress creates a fresh address within default gap limit so it
// should be used soon. Multiple calls will return the same address until that
// address is used (broadcasted)
func (gw *goeleWallet) externalAddress() (btcutil.Address, error) {
	addr, err := gw.wallet.GetUnusedAddress(gw.ctx)
	if err != nil {
		return nil, err
	}
	return gw.decodeAddr(addr, gw.chainParams)
}

// changeAddress creates a fresh change address within the default gap limit so it
// should be used soon. Multiple calls will return the same address until that
// address is used (broadcasted)
// Part of btc.Wallet interface.
func (gw *goeleWallet) changeAddress() (btcutil.Address, error) {
	addr, err := gw.wallet.GetUnusedChangeAddress(gw.ctx)
	if err != nil {
		return nil, err
	}
	return gw.decodeAddr(addr, gw.chainParams)
}

// part of btc.Wallet interface
func (gw *goeleWallet) signTx(inTx *wire.MsgTx) (*wire.MsgTx, error) {
	b, err := serializeMsgTx(inTx)
	if err != nil {
		return nil, err
	}
	signedTx, err := gw.wallet.SignTx(b)
	if err != nil {
		return nil, err
	}
	return msgTxFromBytes(signedTx)
}

type hashRipemd160er interface {
	Hash160() *[20]byte
}

type publicKeyer interface {
	PubKey() *btcec.PublicKey
}

// part of btc.Wallet interface
func (gw *goeleWallet) privKeyForAddress(addr string) (*btcec.PrivateKey, error) {
	addrDec, err := gw.decodeAddr(addr, gw.chainParams)
	if err != nil {
		return nil, err
	}
	wifStr, err := gw.wallet.GetPrivKeyForAddress(addr)
	if err != nil {
		return nil, err
	}
	wif, err := btcutil.DecodeWIF(wifStr)
	if err != nil {
		return nil, err
	} // wif.PrivKey is the result

	// Sanity check that PrivKey corresponds to the pubkey(hash).
	var pkh []byte
	switch addrT := addrDec.(type) {
	case publicKeyer: // e.g. *btcutil.AddressPubKey:
		// Get same format as wif.SerializePubKey()
		var pk []byte
		if wif.CompressPubKey {
			pk = addrT.PubKey().SerializeCompressed()
		} else {
			pk = addrT.PubKey().SerializeUncompressed()
		}
		pkh = btcutil.Hash160(pk) // addrT.ScriptAddress() would require SetFormat(compress/uncompress)
	case *btcutil.AddressScriptHash, *btcutil.AddressWitnessScriptHash:
		return wif.PrivKey, nil // assume unknown redeem script references this pubkey
	case hashRipemd160er: // p2pkh and p2wpkh
		pkh = addrT.Hash160()[:]
	}
	wifPKH := btcutil.Hash160(wif.SerializePubKey())
	if !bytes.Equal(pkh, wifPKH) {
		return nil, errors.New("pubkey mismatch")
	}
	return wif.PrivKey, nil
}

// Previous wallet logic worked but has side effects in goele
// database with getunusedaddress.
// Goele wallet must have a password up front. There is no load
// and unload of different wallets. The configured wallet in
// goele config or default location is used. It is a very simple
// electrum wallet. But the wallet always needs a password.
// We satisfy btc.Wallet interface only here with the bitcoin-cli
// style requirements.

// walletLock locks the wallet. Part of the btc.Wallet interface.
func (gw *goeleWallet) walletLock() error {
	gw.pwMtx.RLock()
	defer gw.pwMtx.RUnlock()
	gw.unlocked = true
	return nil
}

// locked indicates if the wallet has been unlocked. Part of the btc.Wallet
// interface.
func (gw *goeleWallet) locked() bool {
	gw.pwMtx.RLock()
	defer gw.pwMtx.RUnlock()
	return !gw.unlocked
}

// walletUnlock attempts to unlock the wallet with the provided password. On
// success, the password is stored and may be accessed via pass or walletPass.
// Part of the btc.Wallet interface.
func (gw *goeleWallet) walletUnlock(pw []byte) error {
	gw.pwMtx.Lock()
	gw.pw, gw.unlocked = string(pw), true
	gw.pwMtx.Unlock()
	return nil
}

// part of the btc.Wallet interface
func (gw *goeleWallet) peerCount() (uint32, error) {
	return 1, nil
}

// part of the btc.Wallet interface
func (gw *goeleWallet) ownsAddress(addr btcutil.Address) (bool, error) {
	addrStr, err := gw.stringAddr(addr, gw.chainParams)
	if err != nil {
		return false, err
	}
	valid, mine, err := gw.wallet.CheckAddress(addrStr)
	if err != nil {
		return false, err
	}
	if !valid { // maybe electrum doesn't know all encodings that btcutil does - Goele uses btcutil for btc
		return false, nil // an error here may prevent reconfiguring a misconfigured wallet - Goele does not reconfigure
	}
	return mine, nil
}

// part of the btc.Wallet interface
func (gw *goeleWallet) syncStatus() (*SyncStatus, error) {
	height, synced := gw.wallet.Tip()
	return &SyncStatus{
		Target:  int32(height), // goele unknown, we do not have peers, yet. SingleNode/MultiNode
		Height:  int32(height),
		Syncing: !synced,
	}, nil
}

// checkWalletTx will get the bytes and confirmations of a wallet transaction.
// For non-wallet transactions, it is normal to see "Exception: Transaction not
// in wallet" in Electrum's parent console, if launched from a terminal.
// Part of the walletTxChecker interface.
func (gw *goeleWallet) checkWalletTx(txid string) ([]byte, uint32, error) {
	// GetWalletTx only works for wallet transactions, while
	// wallet.GetRawTransaction will try the wallet DB first, but fall back to
	// querying a server, so do GetWalletTx first to prevent that.
	//
	// 'needSync' is returned if wallet tip is known to be behind electrumx
	confs, needSync, _, err := gw.wallet.GetWalletTx(txid)
	if err != nil {
		if !needSync {
			// 'no such transaction'
			return nil, 0, err
		}
	}
	txRaw, err := gw.wallet.GetRawTransaction(gw.ctx, txid)
	if err != nil {
		return nil, 0, err
	}
	if confs < 0 {
		confs = 0
	}
	return txRaw, uint32(confs), nil
}

// part of the walletTxChecker interface
func (gw *goeleWallet) getWalletTransaction(txHash *chainhash.Hash) (*GetTransactionResult, error) {
	// Try the wallet first. If it is not a wallet transaction or if it is
	// confirmed, fall back to the chain method to get the block info and time
	// fields.
	txid := txHash.String()
	txRaw, confs, err := gw.checkWalletTx(txid)
	if err == nil && confs == 0 {
		return &GetTransactionResult{
			TxID:  txid,
			Bytes: txRaw,
			// Time/TimeReceived? now? needed?
		}, nil
	} // else we have to ask a server for the verbose response with block info

	txInfo, err := gw.wallet.GetTransaction(gw.ctx, txid)
	if err != nil {
		return nil, err
	}
	txRaw = txInfo.TxBytes
	return &GetTransactionResult{
		Confirmations: uint64(txInfo.Confirmations),
		BlockHash:     txInfo.BlockHash,
		// BlockIndex unknown
		BlockTime:    uint64(txInfo.BlockTime),
		TxID:         txInfo.TxID, // txHash.String()
		Time:         uint64(txInfo.Time),
		TimeReceived: uint64(txInfo.Time),
		Bytes:        txRaw,
	}, nil
}

// part of the walletTxChecker interface
func (gw *goeleWallet) swapConfirmations(txHash *chainhash.Hash, vout uint32, contract []byte, startTime time.Time) (confs uint32, spent bool, err error) {
	// To determine if it is spent, we need the address of the output.
	var pkScript []byte
	txid := txHash.String()
	// Try the wallet first in case this is a wallet transaction (own swap).
	txRaw, confs, err := gw.checkWalletTx(txid)
	if err == nil {
		msgTx, err := msgTxFromBytes(txRaw)
		if err != nil {
			return 0, false, err
		}
		if vout >= uint32(len(msgTx.TxOut)) {
			return 0, false, fmt.Errorf("output %d of tx %v does not exists", vout, txid)
		}
		pkScript = msgTx.TxOut[vout].PkScript
	} else {
		// Fall back to the more expensive server request.
		txInfo, err := gw.wallet.GetTransaction(gw.ctx, txid)
		if err != nil {
			return 0, false, err
		}
		confs = uint32(txInfo.Confirmations)
		if txInfo.Confirmations < 1 { // TODO: why?
			confs = 0
		}
		if vout >= uint32(len(txInfo.Tx.TxOut)) {
			return 0, false, fmt.Errorf("output %d of tx %v does not exists", vout, txid)
		}
		txOut := txInfo.Tx.TxOut[vout]
		pkScript = txOut.PkScript
	}

	spent, err = gw.outputIsSpent(gw.ctx, txHash, vout, pkScript)
	if err != nil {
		return 0, false, err
	}
	return confs, spent, nil
}

func (gw *goeleWallet) outPointAddress(ctx context.Context, txid string, vout uint32) (string, error) {
	txRaw, err := gw.wallet.GetRawTransaction(ctx, txid)
	if err != nil {
		return "", err
	}
	msgTx, err := msgTxFromBytes(txRaw)
	if err != nil {
		return "", err
	}
	if vout >= uint32(len(msgTx.TxOut)) {
		return "", fmt.Errorf("output %d of tx %v does not exists", vout, txid)
	}
	pkScript := msgTx.TxOut[vout].PkScript
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, gw.chainParams)
	if err != nil {
		return "", fmt.Errorf("invalid pkScript: %v", err)
	}
	if len(addrs) != 1 {
		return "", fmt.Errorf("invalid pkScript: %d addresses", len(addrs))
	}
	addrStr, err := gw.stringAddr(addrs[0], gw.chainParams)
	if err != nil {
		return "", err
	}
	return addrStr, nil
}

func isMempoolTx(h *goele.AddressHistory) bool {
	// has a valid Fee field (omitempty)
	// Height: 0 if all inputs are confirmed, and -1 otherwise
	return h.Fee != nil && (h.Height == 0 || h.Height == -1)
}

func (gw *goeleWallet) findOutputSpender(ctx context.Context, txHash *chainhash.Hash, vout uint32) (*wire.MsgTx, uint32, error) {
	txid := txHash.String()
	addr, err := gw.outPointAddress(ctx, txid, vout)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid outpoint address: %w", err)
	}
	// NOTE: Caller should already have determined the output is spent before
	// requesting the entire address history.
	hist, err := gw.wallet.GetAddressHistory(ctx, addr)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to get address history: %w", err)
	}

	sort.Slice(hist, func(i, j int) bool {
		return hist[i].Height > hist[j].Height // descending
	})

	var outHeight int64
	for _, io := range hist {
		if io.TxHash == txid {
			outHeight = io.Height
			continue // same txn
		}
		if io.Height < outHeight {
			if !isMempoolTx(io) {
				break // spender not before the output's txn
			}
		}
		txRaw, err := gw.wallet.GetRawTransaction(ctx, io.TxHash)
		if err != nil {
			gw.log.Warnf("Unable to retrieve transaction %v for address %v: %v",
				io.TxHash, addr, err)
			continue
		}
		msgTx, err := msgTxFromBytes(txRaw)
		if err != nil {
			gw.log.Warnf("Unable to decode transaction %v for address %v: %v",
				io.TxHash, addr, err)
			continue
		}
		for vin, txIn := range msgTx.TxIn {
			prevOut := &txIn.PreviousOutPoint
			if vout == prevOut.Index && prevOut.Hash.IsEqual(txHash) {
				return msgTx, uint32(vin), nil
			}
		}
	}
	fmt.Printf("findOutputSpender %s:%d caller should check msgTx (internal method)\n", txHash.String(), vout)
	return nil, 0, nil // caller should check msgTx (internal method)
}
