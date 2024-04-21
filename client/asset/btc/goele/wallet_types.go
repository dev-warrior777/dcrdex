// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package goele

import (
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// AddressHistory is an element of the array returned by the
// getaddresshistory RPC.
type AddressHistory struct {
	Height int64  `json:"height"` // 0 when unconfirmed, can be -1 for mempool
	TxHash string `json:"tx_hash"`
	Fee    *int64 `json:"fee,omitempty"` // set when unconfirmed, 'should not be <=0' ;-)
}

// AddressUnspent is an element of the array returned by the
// getaddressunspent RPC.
type AddressUnspent struct { // todo: check unconfirmed fields
	Height int64  `json:"height"`
	TxHash string `json:"tx_hash"`
	TxPos  int32  `json:"tx_pos"`
	Value  int64  `json:"value"`
}

// ListUnspent is similar to an element of the array returned by the electrum
// listunspent RPC.
type ListUnspent struct {
	Address       string
	PkScript      []byte
	Value         float64
	Height        int64
	PrevOutHash   string
	PrevOutIdx    uint32
	RedeemScript  string
	WitnessScript string
	Frozen        bool
	// PartSigs ? "part_sigs": {},
	// BIP32Paths string    `json:"bip32_paths"`
	// Sighash "sighash": null,
	// "unknown_psbt_fields": {},
	// "utxo": null,
	// "witness_utxo": null
}

type Spent struct {
	// Spent utxo
	UtxoOp           *wire.OutPoint
	UtxoAtHeight     int64
	UtxoValue        int64
	UtxoScriptPubkey []byte
	// The height at which it was spent
	SpendHeight int64
	// The tx that consumed it
	SpendTxid *chainhash.Hash
}

// Transaction is the data from a server transaction request.
type Transaction struct {
	TxID          string
	TxBytes       []byte
	Tx            *wire.MsgTx
	Version       uint32
	Size          uint32
	VSize         uint32
	Weight        uint32
	LockTime      uint32
	BlockHash     string
	Confirmations int32
	Time          int64
	BlockTime     int64 // same as Time?
}

// Balance is the result of the balance api.
type Balance struct {
	Confirmed   float64 // not reduced by spends until the txn is confirmed
	Unconfirmed float64 // will be negative for sends? probably, will check db txns
	Immature    float64 // for now goele is mature when mined conf=1.
	Locked      float64 // locked balance .. cannot use the loked utxos
}
