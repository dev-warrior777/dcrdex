// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

//go:build goelelive

package btc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"decred.org/dcrdex/client/asset"
	"decred.org/dcrdex/dex"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// This test uses a regtest BTC Goele wallet.
// - Run btc + electrumX regtest harness nodes
// - use goele mkwallet tool to create a wallet
// - mine regtest harness

func TestGoeleExchangeWalletRegtest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tLogger = dex.StdOutLogger("GOELE-TEST", dex.LevelTrace)
	notes := make(chan asset.WalletNotification, 1)
	walletCfg := &asset.WalletConfig{
		Type: walletTypeElectrum,
		Settings: map[string]string{
			// when you load an goele wallet client you need the pw
			"pw": "abc",
		},
		Emit: asset.NewWalletEmitter(notes, BipID, tLogger),
		PeersChange: func(num uint32, err error) {
			t.Logf("peer count = %d, err = %v", num, err)
		},
	}
	cfg := &BTCCloneCFG{
		WalletCFG:           walletCfg,
		Symbol:              "btc",
		Logger:              tLogger,
		ChainParams:         &chaincfg.RegressionNetParams,
		WalletInfo:          WalletInfo,
		DefaultFallbackFee:  defaultFee,
		DefaultFeeRateLimit: defaultFeeRateLimit,
		Segwit:              true,
		// GoeleWallet constructor overrides btc.localFeeRate = gew.walletFeeRate
	}
	gew, err := GoeleWallet(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// For this to work you need to create/recreate a regtest wallet using
	// goele tools in go-electrum-client/cmd/mkwallet/
	wg, err := gew.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	feeRate := gew.FeeRate()
	if feeRate == 0 {
		t.Fatal("zero fee rate")
	}
	tLogger.Info("feeRate:", feeRate)

	hdrs, err := gew.gw.wallet.GetBlockHeaders(0, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i, hdr := range hdrs {
		tLogger.Infof("%d %s", i, hdr.BlockHash().String())
	}

	// extend this if manual mining
	timeout := time.After(7 * time.Second)
done:
	for {
		select {
		case <-timeout:
			cancel()
			break done
		case <-ctx.Done():
			break done
		// manually mining on regtest node gets us here...
		// mine at least 2 for the first mine to kick electrumX server to notify.
		case ni := <-notes:
			fmt.Println("Note")
			if tcn, is := ni.(*asset.TipChangeNote); is {
				fmt.Println("TipChangeNote", tcn.AssetID, tcn.Tip)
			}
		}
	}
	wg.Wait()
}

// This test uses a testnet BTC Goele wallet.
func TestGoeleExchangeWalletTestnet(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tLogger = dex.StdOutLogger("GOELE-TEST", dex.LevelTrace)
	notes := make(chan asset.WalletNotification, 1)
	walletCfg := &asset.WalletConfig{
		Type: walletTypeElectrum,
		Settings: map[string]string{
			"pw": "abc",
		},
		Emit: asset.NewWalletEmitter(notes, BipID, tLogger),
		PeersChange: func(num uint32, err error) {
			t.Logf("peer count = %d, err = %v", num, err)
		},
	}
	cfg := &BTCCloneCFG{
		WalletCFG:           walletCfg,
		Symbol:              "btc",
		Logger:              tLogger,
		ChainParams:         &chaincfg.TestNet3Params,
		WalletInfo:          WalletInfo,
		DefaultFallbackFee:  defaultFee,
		DefaultFeeRateLimit: defaultFeeRateLimit,
		Segwit:              true,
		// GoeleWallet constructor overrides btc.localFeeRate = gew.walletFeeRate
	}
	gew, err := GoeleWallet(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// For this to work you need to create/recreate a testnet3 wallet using
	// goele tools in go-electrum-client/cmd/mkwallet/
	wg, err := gew.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	feeRate := gew.FeeRate()
	if feeRate == 0 {
		t.Fatal("zero fee rate")
	}
	tLogger.Info("feeRate:", feeRate)

	res, err := gew.gw.wallet.GetTransaction(ctx, "581d837b8bcca854406dc5259d1fb1e0d314fcd450fb2d4654e78c48120e0135")
	if err != nil {
		t.Fatal(err)
	}
	tLogger.Info("returned TxID ", res.TxID)

	hdrs, err := gew.gw.wallet.GetBlockHeaders(2560000, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i, hdr := range hdrs {
		tLogger.Infof("%d %s", i, hdr.BlockHash().String())
	}

	spents, _ := gew.gw.wallet.GetWalletSpents()
	for _, spent := range spents {
		tLogger.Infof("%d %s", spent.SpendHeight, spent.SpendTxid.String())
	}

	// findRedemption
	swapTxHash, _ := chainhash.NewHashFromStr("1e99930f76638e3eddd79de94bf0ff574c7a400d1e6986cd61b3b5fd8212b1a3")
	swapVout := uint32(0)
	redeemTxHash, _ := chainhash.NewHashFromStr("4283c1fefa4898eb1bd2041547cd6361f8167dec004890b58ba1817914dc8541")
	redeemVin := uint32(0)
	// P2WSH: tb1q9vqw464klshj80vklss0ms4h82082y8q86x8cen3934r7zrvt6vs4e3m8u / 00202b00eaeab6fc2f23bd96fc20fdc2b73a9e7510e03e8c7c66712c6a3f086c5e99
	// contract: 6382012088a820135a45665765d68dc255ecd5f1870a1b29b8f1fd95c1e02ca5151e354d2a2cf68876a9144fdb2cad8e98983b25675d3ebe2133e650c56dbf6704ecb0d262b17576a9144fdb2cad8e98983b25675d3ebe2133e650c56dbf6888ac
	contract, _ := hex.DecodeString("6382012088a820135a45665765d68dc255ecd5f1870a1b29b8f1fd95c1e02ca5151e354d2a2cf68876a9144fdb2cad8e98983b25675d3ebe2133e650c56dbf6704ecb0d262b17576a9144fdb2cad8e98983b25675d3ebe2133e650c56dbf6888ac")
	// contractHash, _ := hex.DecodeString("2b00eaeab6fc2f23bd96fc20fdc2b73a9e7510e03e8c7c66712c6a3f086c5e99")
	contractHash := sha256.Sum256(contract)
	wantSecret, _ := hex.DecodeString("aa8e04bb335da65d362b89ec0630dc76fd02ffaca783ae58cb712a2820f504ce")
	foundTxHash, foundVin, secret, err := gew.findRedemption(ctx, NewOutPoint(swapTxHash, swapVout), contractHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, wantSecret) {
		t.Errorf("incorrect secret %x, wanted %x", secret, wantSecret)
	}
	if !foundTxHash.IsEqual(redeemTxHash) {
		t.Errorf("incorrect redeem tx hash %v, wanted %v", foundTxHash, redeemTxHash)
	}
	if redeemVin != foundVin {
		t.Errorf("incorrect redeem tx input %d, wanted %d", foundVin, redeemVin)
	}

	// FindRedemption
	redeemCoin, secretBytes, err := gew.FindRedemption(ctx, ToCoinID(swapTxHash, swapVout), contract)
	if err != nil {
		t.Fatal(err)
	}
	foundTxHash, foundVin, err = decodeCoinID(redeemCoin)
	if err != nil {
		t.Fatal(err)
	}
	if !foundTxHash.IsEqual(redeemTxHash) {
		t.Errorf("incorrect redeem tx hash %v, wanted %v", foundTxHash, redeemTxHash)
	}
	if redeemVin != foundVin {
		t.Errorf("incorrect redeem tx input %d, wanted %d", foundVin, redeemVin)
	}
	if !secretBytes.Equal(wantSecret) {
		t.Errorf("incorrect secret %v, wanted %x", secretBytes, wantSecret)
	}

	t.Logf("Found redemption of contract %v:%d at %v:%d!", swapTxHash, swapVout, foundTxHash, foundVin)

	timeout := time.After(7 * time.Second)
done:
	for {
		select {
		case <-timeout:
			cancel()
			break done
		case <-ctx.Done():
			break done
		case ni := <-notes:
			fmt.Println("Note")
			if tcn, is := ni.(*asset.TipChangeNote); is {
				fmt.Println("TipChangeNote", tcn.AssetID, tcn.Tip)
			}
		}
	}
	wg.Wait()
}
