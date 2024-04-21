///////go:build harness,goelelivetest

package goelelivetest

import (
	"fmt"
	"testing"

	"decred.org/dcrdex/client/asset/btc"
	"decred.org/dcrdex/dex"
	dexbtc "decred.org/dcrdex/dex/networks/btc"
)

const (
// alphaAddress  = "bcrt1q9af9hzt8f9j3cy9gtyq3ntkj3udwjtucmf7g3t"
// walletTypeSPV = "SPV"
)

var (
	tBTC = &dex.Asset{
		ID:           0,
		Symbol:       "btc",
		Version:      0, // match btc.version
		SwapSize:     dexbtc.InitTxSizeSegwit,
		SwapSizeBase: dexbtc.InitTxSizeBaseSegwit,
		MaxFeeRate:   10,
		SwapConf:     1,
	}
)

func TestGoeleWallet(t *testing.T) {
	const lotSize = 1e6

	fmt.Println("////////// GOELE & RPC WALLET W/O SPLIT //////////")
	Run(t, &Config{
		NewWallet: btc.NewWallet,
		LotSize:   lotSize,
		Asset:     tBTC,
		SplitTx:   false,
		SPV:       false,
		FirstWallet: &WalletName{
			Node: "alpha",
		},
		SecondWallet: &WalletName{
			Node:       "goele",
			Name:       "electrum",
			WalletType: "walletTypeElectrum",
		},
	})
}
