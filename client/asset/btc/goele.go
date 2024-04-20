// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package btc

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"decred.org/dcrdex/client/asset"
	"decred.org/dcrdex/client/asset/btc/goele"
	"decred.org/dcrdex/dex"
	"decred.org/dcrdex/dex/config"
	dexbtc "decred.org/dcrdex/dex/networks/btc"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// ExchangeWalletGoele is the asset.Wallet for an external Electrum wallet: Goele.
type ExchangeWalletGoele struct {
	*baseWallet
	*authAddOn
	gw *goeleWallet

	findRedemptionMtx   sync.RWMutex
	findRedemptionQueue map[OutPoint]*FindRedemptionReq
}

var _ asset.Wallet = (*ExchangeWalletGoele)(nil)
var _ asset.Authenticator = (*ExchangeWalletGoele)(nil)

// GoeleWallet creates a new ExchangeWalletGoele for the provided
// configuration, which must contain the necessary details for accessing the
// Goele electrum wallet.
func GoeleWallet(cfg *BTCCloneCFG) (*ExchangeWalletGoele, error) {
	clientCfg := new(WalletConfig)
	err := config.Unmapify(cfg.WalletCFG.Settings, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("error parsing wallet config: %w", err)
	}
	pw := cfg.WalletCFG.Settings["pw"]
	if pw == "" {
		return nil, errors.New("cannot load wallet")
	}

	btc, err := newUnconnectedWallet(cfg, clientCfg)
	if err != nil {
		return nil, err
	}

	gwc, err := goele.NewWalletClient(cfg.Symbol, cfg.ChainParams, pw)
	if err != nil {
		return nil, err
	}

	gw := newGoeleWallet(&gwc, &goeleWalletConfig{
		params:       cfg.ChainParams,
		log:          cfg.Logger.SubLogger("GOELE"),
		addrDecoder:  cfg.AddressDecoder,
		addrStringer: cfg.AddressStringer,
		segwit:       cfg.Segwit,
		wc:           gwc,
	})
	btc.setNode(gw)

	gew := &ExchangeWalletGoele{
		baseWallet:          btc,
		authAddOn:           &authAddOn{btc.node},
		gw:                  gw,
		findRedemptionQueue: make(map[OutPoint]*FindRedemptionReq),
	}
	// In (*baseWallet).feeRate, use ExchangeWalletGoele's walletFeeRate
	// override for localFeeRate. No externalFeeRate is required but will be
	// used if gew.walletFeeRate returned an error and an externalFeeRate is
	// enabled.
	btc.localFeeRate = gew.walletFeeRate

	return gew, nil
}

// DepositAddress returns an address for depositing funds into the exchange
// wallet. The address will be unused but not necessarily new. Use NewAddress to
// request a new address, but it should be used immediately.
func (btc *ExchangeWalletGoele) DepositAddress() (string, error) {
	return btc.gw.wallet.GetUnusedAddress(btc.gw.ctx)
}

// RedemptionAddress gets an address for use in redeeming the counterparty's
// swap. This would be included in their swap initialization. The address will
// be unused but not necessarily new because these addresses often go unused.
func (btc *ExchangeWalletGoele) RedemptionAddress() (string, error) {
	return btc.gw.wallet.GetUnusedAddress(btc.gw.ctx)
}

// Connect connects to the Goele wallet client.
//
// Goroutines are started to monitor for new blocks and peers.
// Satisfies the dex.Connector interface.
func (btc *ExchangeWalletGoele) Connect(ctx context.Context) (*sync.WaitGroup, error) {
	wg, err := btc.connect(ctx) // prepares btc.gw.chainV via (our) btc.node.connect()
	if err != nil {
		return nil, err
	}
	tipChangeRcv, err := btc.gw.wallet.RegisterTipChangeNotify()
	if err != nil {
		return nil, err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		btc.watchBlocks(ctx, tipChangeRcv) // ExchangeWalletGoele override
		btc.cancelRedemptionSearches()
		btc.gw.wallet.UnregisterTipChangeNotify()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		btc.monitorPeers(ctx)
	}()

	return wg, nil
}

func (btc *ExchangeWalletGoele) cancelRedemptionSearches() {
	// Close all open channels for contract redemption searches
	// to prevent leakages and ensure goroutines that are started
	// to wait on these channels end gracefully.
	btc.findRedemptionMtx.Lock()
	for contractOutpoint, req := range btc.findRedemptionQueue {
		req.fail("shutting down")
		delete(btc.findRedemptionQueue, contractOutpoint)
	}
	btc.findRedemptionMtx.Unlock()
}

// walletFeeRate satisfies BTCCloneCFG.FeeEstimator.
func (btc *ExchangeWalletGoele) walletFeeRate(ctx context.Context, _ RawRequester, confTarget uint64) (uint64, error) {
	satPerKB, err := btc.gw.wallet.FeeRate(ctx, int64(confTarget))
	if err != nil {
		return 0, err
	}
	return uint64(dex.IntDivUp(satPerKB, 1000)), nil
}

// findRedemption will search for the spending transaction of specified
// outpoint. If found, the secret key will be extracted from the input scripts.
// If not found, but otherwise without an error, a nil Hash will be returned
// along with a nil error. Thus, both the error and the Hash should be checked.
// This convention is only used since this is not part of the public API.
func (btc *ExchangeWalletGoele) findRedemption(ctx context.Context, op OutPoint, contractHash []byte) (*chainhash.Hash, uint32, []byte, error) {
	msgTx, vin, err := btc.gw.findOutputSpender(ctx, &op.TxHash, op.Vout)
	if err != nil {
		return nil, 0, nil, err
	}
	if msgTx == nil {
		return nil, 0, nil, nil
	}
	txHash := msgTx.TxHash()
	txIn := msgTx.TxIn[vin]
	secret, err := dexbtc.FindKeyPush(txIn.Witness, txIn.SignatureScript,
		contractHash, btc.segwit, btc.chainParams)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to extract secret key from tx %v input %d: %w",
			txHash, vin, err) // name the located tx in the error since we found it
	}
	return &txHash, vin, secret, nil
}

// called as a goroutine
func (btc *ExchangeWalletGoele) tryRedemptionRequests(ctx context.Context) {
	btc.findRedemptionMtx.RLock()
	reqs := make([]*FindRedemptionReq, 0, len(btc.findRedemptionQueue))
	for _, req := range btc.findRedemptionQueue {
		reqs = append(reqs, req)
	}
	btc.findRedemptionMtx.RUnlock()

	for _, req := range reqs {
		txHash, vin, secret, err := btc.findRedemption(ctx, req.outPt, req.contractHash)
		if err != nil {
			req.fail("findRedemption: %w", err)
			continue
		}
		if txHash == nil {
			continue // maybe next time
		}
		req.success(&FindRedemptionResult{
			redemptionCoinID: ToCoinID(txHash, vin),
			secret:           secret,
		})
	}
}

// FindRedemption locates a swap contract output's redemption transaction input
// and the secret key used to spend the output.
func (btc *ExchangeWalletGoele) FindRedemption(ctx context.Context, coinID, contract dex.Bytes) (redemptionCoin, secret dex.Bytes, err error) {
	txHash, vout, err := decodeCoinID(coinID)
	if err != nil {
		return nil, nil, err
	}
	contractHash := btc.hashContract(contract)
	// We can verify the contract hash via:
	// txRes, _ := btc.gw.getWalletTransaction(txHash)
	// msgTx, _ := msgTxFromBytes(txRes.Hex)
	// contractHash := dexbtc.ExtractScriptHash(msgTx.TxOut[vout].PkScript)
	// OR
	// txOut, _, _ := btc.gw.getTxOutput(txHash, vout)
	// contractHash := dexbtc.ExtractScriptHash(txOut.PkScript)

	// Check once before putting this in the queue.
	outPt := NewOutPoint(txHash, vout)
	spendTxID, vin, secret, err := btc.findRedemption(ctx, outPt, contractHash)
	if err != nil {
		return nil, nil, err
	}
	if spendTxID != nil {
		return ToCoinID(spendTxID, vin), secret, nil
	}
	//----------------------------------------------

	req := &FindRedemptionReq{
		outPt:        outPt,
		resultChan:   make(chan *FindRedemptionResult, 1),
		contractHash: contractHash,
		// blockHash, blockHeight, and pkScript not used by this impl.
		blockHash: &chainhash.Hash{},
	}
	if err := btc.queueFindRedemptionRequest(req); err != nil {
		return nil, nil, err
	}

	var result *FindRedemptionResult
	select {
	case result = <-req.resultChan:
		if result == nil {
			err = fmt.Errorf("unexpected nil result for redemption search for %s", outPt)
		}
	case <-ctx.Done():
		err = fmt.Errorf("context cancelled during search for redemption for %s", outPt)
	}

	// If this contract is still in the findRedemptionQueue, remove from the
	// queue to prevent further redemption search attempts for this contract.
	btc.findRedemptionMtx.Lock()
	delete(btc.findRedemptionQueue, outPt)
	btc.findRedemptionMtx.Unlock()

	// result would be nil if ctx is canceled or the result channel is closed
	// without data, which would happen if the redemption search is aborted when
	// this ExchangeWallet is shut down.
	if result != nil {
		return result.redemptionCoinID, result.secret, result.err
	}
	return nil, nil, err
}

func (btc *ExchangeWalletGoele) queueFindRedemptionRequest(req *FindRedemptionReq) error {
	btc.findRedemptionMtx.Lock()
	defer btc.findRedemptionMtx.Unlock()
	if _, exists := btc.findRedemptionQueue[req.outPt]; exists {
		return fmt.Errorf("duplicate find redemption request for %s", req.outPt)
	}
	btc.findRedemptionQueue[req.outPt] = req
	return nil
}

// watchBlocks pings for new blocks and runs the tipChange callback function
// when the block changes. Goele supplies tip changes from it's subscription.

func (btc *ExchangeWalletGoele) watchBlocks(ctx context.Context, tipChange <-chan int64) {
	currentTip, synced := btc.gw.wallet.Tip()
	btc.log.Debugf("starting block watch - current tip %d headers synced %v\n", currentTip, synced)

	for {
		select {
		case newTip := <-tipChange:
			btc.emit.TipChange(uint64(newTip))
			currentTip = newTip
			go btc.tryRedemptionRequests(ctx)
		case <-ctx.Done():
			return
		}
	}
}
