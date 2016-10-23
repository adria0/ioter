package main

import (
	"bytes"
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
	"net/http"
)

const (
	keyFilename        = "key.json"
	gethRpcUrl         = "http://localhost:8545"
	coinbaseStr        = "0x018ec086ab7e050e203bff70c876b8f5638f7dc1"
	contractAddressStr = "0x761d5802117ab2ed96c6595c9efe4defadf67857"
	account1Str        = "0x9607e022978dee708567e8f4321fe2cb9d980cb5"
)

var (
	coinbase        common.Address
	contractAddress common.Address
	account1        common.Address
)

func init() {
	coinbase = common.HexToAddress(coinbaseStr)
	contractAddress = common.HexToAddress(contractAddressStr)
	account1 = common.HexToAddress(account1Str)
}

func assert(err error) {
	if err != nil {
		panic("Failed: " + err.Error())
	}
}

type gethRpcCall struct {
	Id      int      `json:"id"`
	Jsonrpc string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
}

type getRpcResponse struct {
	Id      int    `json:"id"`
	Jsonrpc string `json:"jsonrpc"`
	Error   *struct {
		Code    int32  `json:"code"`
		Message string `json:"message"`
	}
	Result *string `json:"result"`
}

func gethRpc(method string, params ...string) (string, error) {

	jsonStr, err := json.Marshal(&gethRpcCall{
		Id:      1,
		Jsonrpc: "2.0",
		Method:  method,
		Params:  params,
	})

	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", gethRpcUrl, bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err

	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	var response getRpcResponse
	err = json.Unmarshal(body, &response)

	if err != nil {
		return "", err
	}
	if response.Error != nil {
		return "", fmt.Errorf("%v:%v", response.Error.Message, response.Error.Code)
	}

	return *response.Result, nil
}

func rpcGetTransactionCount(address common.Address) (uint64, error) {

	result, err := gethRpc(
		"eth_getTransactionCount",
		address.Hex(),
		"pending",
	)

	if err != nil {
		return 0, err
	}

	return common.ReadVarInt(common.FromHex(result)), nil
}

func rpcGasPrice() (*big.Int, error) {

	result, err := gethRpc(
		"eth_gasPrice",
	)

	if err != nil {
		return nil, err
	}

	return common.Bytes2Big(common.FromHex(result)), nil
}

func rpcSendRawTransaction(signedTransaction []byte) error {

	_, err := gethRpc(
		"eth_sendRawTransaction",
		common.ToHex(signedTransaction),
	)

	return err

}

func marshallSendWei(toWhom common.Address) []byte {

	// the Method ID. This is derived as the first 4 bytes of the
	//   Keccak hash of the ASCII form of the signature baz(uint32,bool).

	def, err := ioutil.ReadFile("contract_abi.json")
	assert(err)

	abi, err := abi.JSON(bytes.NewReader(def))
	assert(err)

	packed, err := abi.Pack("sendWei", toWhom)

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

	log.Println("Local address is ", key.Address.Hex())
	log.Println("Contract address is ", contractAddress.Hex())
	log.Println("Contract destination is ", account1.Hex())

	gasPrice, err := rpcGasPrice()
	assert(err)
	log.Println("Gas price is ", gasPrice)

	nonce, err := rpcGetTransactionCount(key.Address)
	log.Println("Transaction count is ", nonce)
	assert(err)

	amount := big.NewInt(0) // common.Ada
	gasLimit := common.Babbage

	data := marshallSendWei(account1)

	tx, err := types.NewTransaction(
		// From is derived from the signature (V, R, S) using secp256k1
		nonce,           // nonce int64
		contractAddress, // contractAddress,       // to common.Address
		amount,          // amount *big.Int
		gasLimit,        // gasLimit *big.Int
		gasPrice,        // gasPrice *big.Int
		data,            // data,     // data []byte
	).SignECDSA(key.PrivateKey)

	assert(err)

	raw, err := rlp.EncodeToBytes(tx)
	assert(err)

	err = rpcSendRawTransaction(raw)
	assert(err)
}
