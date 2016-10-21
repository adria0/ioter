package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/pborman/uuid"
	"io/ioutil"
	"log"
	"math/big"
	"strings"
)

const (
	keyFilename = "key.json"
    gethRpcUrl = ""
)

func assert(err error) {
	if err != nil {
		panic("Failed: " + err.Error())
	}
}

type gethRpcCall struct {
    id      int
    jsonrpc string
    method  string
    params  []string
}

func gethRpc(method string, params ...string) (string,error) {

    jsonStr, err := json.Marshal(&gethRpcCall {
        id :1,
        jsonrpc: "2.0"
        method: method,
        params : params,
    })

    if err != nil {
        return nil,err
    }

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil,err

	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

    return body, nil
}

func rpcGetTransactionCount(address Address) uint64 {

	err, body := gethRpc(
        "eth_getTransactionCount",
        address.Hex(),
        "lastest",
    )

	return 1
}

func rpcSendRawTransaction(signedtransactionHex string)  {

    err, body := gethRpc(
        "eth_sendRawTransaction",
        signedtransactionHex,
    )

}

func NewBigInt(base10 string) *big.Int {
	v := new(big.Int)
	v.SetString(base10, 10)
	return v
}

// Encodes a call to onevent(uint32)
func abiEncode(v uint32) []byte {

	// the Method ID. This is derived as the first 4 bytes of the
	//   Keccak hash of the ASCII form of the signature baz(uint32,bool).

	def := `
    [{
        "constant":true,
        "inputs":[
            {"name":"","type":"uint32"}
        ],
        "name":"onevent",
        "outputs":[
        ],
        "type":"function"
    }]`

	abi, err := abi.JSON(strings.NewReader(def))
	assert(err)

	packed, err := abi.Pack("onevent", v)

	return packed
}

func newKey() (*accounts.Key, error) {

	var err error

	privateKeyECDSA, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, err

	}

	id := uuid.NewRandom()
	key := &accounts.Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		PrivateKey: privateKeyECDSA,
	}

	content, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}

	err = ioutil.WriteFile(keyFilename, content, 0600)
	if err != nil {
		return nil, err
	}

	log.Println("Created new P256K1 key")

	return key, nil

}

func loadKey() (*accounts.Key, error) {

	content, err := ioutil.ReadFile(keyFilename)
	if err != nil {
		return nil, err
	}

	var key accounts.Key
	err = json.Unmarshal(content, &key)
	if err != nil {
		return nil, err
	}

	log.Println("Loaded P256K1 key")

	return &key, nil

}

func main() {

	var err error
	var key *accounts.Key

	if key, err = loadKey(); err != nil {
		if key, err = newKey(); err != nil {
			assert(err)
		}
	}

	log.Println("Address is ", key.Address.Hex())

	nonce := rpcGetTransactionCount(key)

	to := common.StringToAddress("0xac6c708bc24755d926583d60d37879f5039dbca0")
	amount := NewBigInt("1000000000000000000")
	gasLimit := NewBigInt("1000000")
	gasPrice := NewBigInt("20000000000")

	data := abiEncode(12)

	tx, err := types.NewTransaction(
		// From is derived from the signature (V, R, S) using secp256k1
		nonce,    // nonce int64
		to,       // to common.Address
		amount,   // amount *big.Int
		gasLimit, // gasLimit *big.Int
		gasPrice, // gasPrice *big.Int
		data,     // data []byte
	).SignECDSA(key.PrivateKey)

	assert(err)

	raw, err := rlp.EncodeToBytes(tx)
	assert(err)

	rpcSendRawTransaction(raw)
	fmt.Println(raw)

}
