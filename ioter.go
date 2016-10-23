package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"net/http"
    "bytes"
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
)

const (
	keyFilename = "key.json"
    gethRpcUrl = "http://localhost:8545"
    coinbaseStr = "0x018ec086ab7e050e203bff70c876b8f5638f7dc1"
    contractAddressStr = "0xa114b4907d669616f75da26f23b65fcc991810d9"
    account1Str = "0x9607e022978dee708567e8f4321fe2cb9d980cb5"
)

var (
    coinbase common.Address
    contractAddress common.Address
    account1 common.Address
)

func init() {
    coinbase = common.StringToAddress(coinbaseStr)
    contractAddress = common.StringToAddress(contractAddressStr)
    account1 = common.StringToAddress(account1Str)
}


func assert(err error) {
	if err != nil {
		panic("Failed: " + err.Error())
	}
}

type gethRpcCall struct {
    Id      int  `json:"id"`
    Jsonrpc string `json:"jsonrpc"`
    Method  string `json:"method"`
    Params  []string `json:"params"`
}

type getRpcResponse struct {
    Id      int  `json:"id"`
    Jsonrpc string `json:"jsonrpc"`
    Error *struct {
         Code int32 `json:"code"`
         Message string `json:"message"`
    }
    Result *string `json:"result"`
}

func gethRpc(method string, params ...string) (string,error) {

    jsonStr, err := json.Marshal(&gethRpcCall {
        Id :1,
        Jsonrpc: "2.0",
        Method: method,
        Params : params,
    })

    if err != nil {
        return "",err
    }

	req, err := http.NewRequest("POST", gethRpcUrl , bytes.NewBuffer(jsonStr))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "",err

	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

    var response getRpcResponse
    err = json.Unmarshal(body,&response)
    fmt.Printf("%v",response)
    if err != nil {
        return "",err
    }
    if response.Error != nil {
        return "", fmt.Errorf("%v:%v",response.Error.Message,response.Error.Code)
    }

    return *response.Result, nil
}

func rpcGetTransactionCount(address common.Address) (uint64,error) {

    result , err := gethRpc(
        "eth_getTransactionCount",
        address.Hex(),
        "pending",
    )

    if err != nil {
         return 0,err
    }

    fmt.Println("Got =>",result)

    return common.ReadVarInt(common.FromHex(result)),nil
}

func rpcSendRawTransaction(signedTransaction []byte) (error) {

    _ , err := gethRpc(
        "eth_sendRawTransaction",
        common.ToHex(signedTransaction),
    )

    return err

}

func NewBigInt(base10 string) *big.Int {
	v := new(big.Int)
	v.SetString(base10, 10)
	return v
}

// Encodes a call to onevent(uint32)
func marshallSendWei(toWhom common.Address) []byte {

	// the Method ID. This is derived as the first 4 bytes of the
	//   Keccak hash of the ASCII form of the signature baz(uint32,bool).

    def,err := ioutil.ReadFile("contract_abi.json")
    assert(err)

    abi, err := abi.JSON(bytes.NewReader(def))
	assert(err)

    fmt.Println( abi )

	packed, err := abi.Pack("sendWei", toWhom)

    fmt.Println("Packed=>",common.ToHex(packed))
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

	nonce,err := rpcGetTransactionCount(key.Address)
    assert(err)

    fmt.Println("trncount=",nonce)

	amount := common.Ada
	gasLimit := common.Babbage
	gasPrice := common.Szabo

	// data := marshallSendWei(account1)

	tx, err := types.NewTransaction(
		// From is derived from the signature (V, R, S) using secp256k1
		nonce,    // nonce int64
		account1, // contractAddress,       // to common.Address
		amount,   // amount *big.Int
		gasLimit, // gasLimit *big.Int
		gasPrice, // gasPrice *big.Int
		nil, // data,     // data []byte
	).SignECDSA(key.PrivateKey)

	assert(err)

	raw, err := rlp.EncodeToBytes(tx)
	assert(err)

	rpcSendRawTransaction(raw)

}

