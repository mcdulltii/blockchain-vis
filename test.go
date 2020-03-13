package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/binary"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

/***********
 * Structs *
 ***********/

// Block contains headers and data
type Block struct {
	Index     int
	Timestamp string
	Data      string
	Hash      string
	PrevHash  string
}

// ProofOfWork represents a proof-of-work
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// Message takes incoming JSON payload for writing heart rate
type Message struct {
	Data string
}


/*************
 * Variables *
 *************/

var Blockchain []Block
var mutex = &sync.Mutex{}
var Nonce int
var maxNonce = math.MaxInt64
var tmpls = template.Must(template.ParseFiles("web/index.html"))

const targetBits = 12 // difficulty setting


/*************
 * Functions *
 *************/

func main() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	go StartBlockchain()

	log.Fatal(run())
}


/************************
 * Blockchain Functions *
 ************************/

/* NewBlock generates and returns a Block */
func NewBlock(oldBlock Block, Data string) Block {

	var block Block

	t := time.Now()

	block.Index = oldBlock.Index + 1
	block.Timestamp = strings.Split(strings.Split(t.String(), "+")[0], ".")[0]
	block.Data = Data
	block.PrevHash = oldBlock.Hash

	pow := NewProofOfWork(&block)
	nonce, hash := pow.RunPOW()

	block.Hash = hex.EncodeToString(hash[:])
	Nonce = nonce

	return block
}


/* StartBlockchain begins the Blockchain, appending a genesis Block */
func StartBlockchain() {
	t := time.Now()
	genesisBlock := Block{}
	genesisBlock = Block{0, strings.Split(strings.Split(t.String(), "+")[0], ".")[0], "Genesis Block", "", ""}

	pow := NewProofOfWork(&genesisBlock)
	nonce, hash := pow.RunPOW()

	genesisBlock.Hash = hex.EncodeToString(hash[:])
	Nonce = nonce

	spew.Dump(genesisBlock)

	mutex.Lock()
	Blockchain = append(Blockchain, genesisBlock)
	mutex.Unlock()

}


/* NewProofOfWork builds and returns a ProofOfWork */
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	pow := &ProofOfWork{b, target}

	return pow
}


/* prepareData formats the data into a byte array */
func (pow *ProofOfWork) prepareData(nonce int) []byte {
	data := bytes.Join(
		[][]byte{
			[]byte(pow.block.PrevHash),
			[]byte(pow.block.Data),
			[]byte(pow.block.Timestamp),
			IntToHex(int64(pow.block.Index)),
			IntToHex(int64(targetBits)),
			IntToHex(int64(nonce)),
		},
		[]byte{},
	)

	return data
}


/* RunPOW performs a proof-of-work */
func (pow *ProofOfWork) RunPOW() (int, []byte) {
	var hashInt big.Int
	var hash [32]byte
	nonce := 0

	fmt.Printf("Mining the block containing \"%s\"\n", pow.block.Data)
	for nonce < maxNonce {
		data := pow.prepareData(nonce)

		hash = sha256.Sum256(data)
		fmt.Printf("\r%x", hash)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {
			nonce++
		}
	}
	fmt.Print("\n\n")

	return nonce, hash[:]
}


/* Validate validates block's Proof of Work */
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int

	data := pow.prepareData(Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])

	isValid := hashInt.Cmp(pow.target) == -1

	return isValid
}


/* IntToHex converts an int64 to a byte array */
func IntToHex(num int64) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}

/************************
 * Web Server Functions *
 ************************/

 /* run will set up a http server */
func run() error {
	mux := makeMuxRouter()
	httpPort := os.Getenv("PORT")
	log.Println("HTTP Server Listening on port :", httpPort)
	s := &http.Server{
		Addr:           ":" + httpPort,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if err := s.ListenAndServe(); err != nil {
		return err
	}

	return nil
}


/* Index sets up the index html page */
func Index(w http.ResponseWriter, r *http.Request) {
	bytes, _ := json.MarshalIndent(Blockchain, "", "  ")
	data := struct {
		Title  string
		Data string
	}{
		Title:  "Blockchain Visualisation",
		Data: strings.ReplaceAll(string(bytes), "\n", ""),
	}

	if err := tmpls.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}


/* makeMuxRouter creates and return a router handler*/
func makeMuxRouter() http.Handler {
	muxRouter := mux.NewRouter()
	// muxRouter.HandleFunc("/", handleGetBlockchain).Methods("GET")
	muxRouter.HandleFunc("/", handleWriteBlock).Methods("POST")
	muxRouter.HandleFunc("/web/", Index)
	muxRouter.PathPrefix("/web/").Handler(http.StripPrefix("/web/", http.FileServer(http.Dir("web/"))))
	return muxRouter
}


/* handleGetBlockchain writes a blockchain when we receive an http request */
func handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	bytes, err := json.MarshalIndent(Blockchain, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, string(bytes))
}


/* handleWriteBlock takes the JSON payload as data input and inserts a new block */
func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var msg Message

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&msg); err != nil {
		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
		return
	}
	defer r.Body.Close()

	mutex.Lock()
	prevBlock := Blockchain[len(Blockchain)-1]
	if msg.Data == "" {
		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
		return
	}
	newBlock := NewBlock(prevBlock, msg.Data)

	pow := NewProofOfWork(&newBlock)

	if pow.Validate() {
		Blockchain = append(Blockchain, newBlock)
		spew.Dump(Blockchain)
	}
	mutex.Unlock()

	respondWithJSON(w, r, http.StatusCreated, newBlock)

}


/* respondWithJSON writes a JSON text back to the web server */
func respondWithJSON(w http.ResponseWriter, r *http.Request, code int, payload interface{}) {
	response, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}
	w.WriteHeader(code)
	w.Write(response)
}