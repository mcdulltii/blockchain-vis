package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
	"github.com/spf13/pflag"
)

/***********
 * Structs *
 ***********/

type Block struct {
	Index     int
	Timestamp string
	Data      string
	Hash      string
	PrevHash  string
	Nonce     int
}

type ProofOfWork struct {
	block  *Block
	target *big.Int
}

type Message struct {
	Data string
}

type Hello struct {
	AddrFrom string
	Purpose  string
}

type Addr struct {
	AddrFrom string
	AddrList []string
}

type GetChain struct {
	AddrFrom string
}

type Chain struct {
	AddrFrom   string
	BlockChain []Block
}

type CheckBlock struct {
	AddrFrom string
	Block    Block
}

/*************
 * Variables *
 *************/

var (
	nodeAddress   string
	httpPort      int
	KnownNodes    []string
	Blockchain    []Block
	mutex         = &sync.Mutex{}
	maxNonce      = math.MaxInt64
	ValidChan     = make(chan bool)
	jsonflag      = false
	broadcastflag = true
	tmpls         = template.Must(template.ParseFiles("web/index.html"))
	hostFlag      = pflag.StringP("host", "h", GetOutboundIP(), "binding host")
	portFlag      = pflag.IntP("port", "p", 4444, "binding port")
	httpPortFlag  = pflag.IntP("webport", "w", 8000, "web server port")
)

const (
	targetBits    = 18 // difficulty setting
	printedLength = 8  // printedLength is the total prefix length of a public key associated to a chat users ID.
	commandLength = 12
	protocol      = "tcp"
	layout        = "2006-01-02 15:04:05"
)

/*************
 * Functions *
 *************/

func main() {
	go StartServer()

	log.Fatal(run())
}

/*****************
 * P2P Functions *
 *****************/

func StartServer() {
	pflag.Parse()

	nodeAddress = fmt.Sprintf("%s:%d", *hostFlag, *portFlag)
	fmt.Printf("You are %s\n", nodeAddress)

	// add self to KnownNodes
	KnownNodes = append(KnownNodes, nodeAddress)

	// Node Discovery begins
	if len(pflag.Args()) == 1 {
		peer := pflag.Args()[0]

		// send hello request to connecting peer, asking for peer's address list
		fmt.Printf("Connecting to %s.\n", peer)
		SendHello(peer, "neighbour")

	} else if len(pflag.Args()) == 0 {
		fmt.Println("No peers to connect to, generating blockchain")
		StartBlockchain()
	} else {
		fmt.Println("Too many arguments! Select a peer.")
		os.Exit(1)
	}

	ln, err := net.Listen(protocol, nodeAddress)
	if err != nil {
		log.Panic(err)
	}

	defer ln.Close()


	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Panic(err)
		}
		go HandleConnection(conn)

	}
}

/* GetOutboundIP is to find ip of host for p2p discovery */
func GetOutboundIP() string {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)

    return localAddr.IP.String()
}

/* HandleConnection is the main handler for any connection to the host */
func HandleConnection(conn net.Conn) {
	req, err := ioutil.ReadAll(conn)
	defer conn.Close()

	if err != nil {
		log.Panic(err)
	}

	command := BytesToCmd(req[:commandLength])
	fmt.Printf("Received %s command\n", command)

	switch command {
	case "hello":
		HandleHello(req)

	case "addr":
		HandleAddr(req)

	case "getchain":
		HandleGetChain(req)

	case "chain":
		HandleChain(req)

	case "checkblock":
		HandleCheckBlock(req)

	default:
		fmt.Println("Unknown command")
	}
}

/* HandleHello handles hello requests which does node discovery.
 * Neighbour is used when a new node does its first communication with a known node to request for their address list.
 * Ping is used to communicate to a node in peer's address list and waits for a pong.
 * Pong is used to confirm a ping to start getting a peer's chain. */
func HandleHello(request []byte) {
	var buff bytes.Buffer
	var payload Hello

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	switch payload.Purpose {
	case "neighbour":
		KnownNodes = append(KnownNodes, payload.AddrFrom)
		fmt.Println(KnownNodes)
		SendAddr(payload.AddrFrom)

	case "ping":
		if !NodeIsKnown(payload.AddrFrom) {
			KnownNodes = append(KnownNodes, payload.AddrFrom)
		}
		fmt.Println(KnownNodes)
		SendHello(payload.AddrFrom, "pong")

	case "pong":
		if broadcastflag {
			broadcastflag = false
			RequestChain()
		}

	default:
		fmt.Println("Unknown Hello Purpose")
	}
}

/* HandleAddr handles Addr request which is a slice of known nodes from a peer.
 * These nodes will be appended to known nodes.
 * Hello ping requests will be sent to newly discovered nodes */
func HandleAddr(request []byte) {
	var buff bytes.Buffer
	var payload Addr

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	// append nodes to KnownNodes
	for _, ip := range payload.AddrList {
		if !NodeIsKnown(ip) {
			KnownNodes = append(KnownNodes, ip)
		}
	}

	// send hello ping requests to newly discovered nodes
	for _, node := range KnownNodes {
		if node != nodeAddress {
			SendHello(node, "ping")
		}
	}
}

/* HandleGetChain handles GetChain requests which is a request for the host's blockchain.
 * host will call SendChain.*/
func HandleGetChain(request []byte) {
	var buff bytes.Buffer
	var payload GetChain

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	SendChain(payload.AddrFrom)
}

/* HandleChain handles chain requests which compares payload blockchain and its own blockchain.
* The longer chain will be the current blockchain.
* jsonflag used to signal isValid in HandleWriteBlock to update web server. */
func HandleChain(request []byte) {
	var buff bytes.Buffer
	var payload Chain

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	// replace BlockChain if payload chain is longer
	if len(payload.BlockChain) > len(Blockchain) {
		fmt.Println("Longer chain detected, replacing current chain")

		Blockchain = payload.BlockChain
		spew.Dump(Blockchain)

		if jsonflag {
			ValidChan <- true
		}

	} else {
		fmt.Println("Discarded new chain")

		if jsonflag {
			ValidChan <- false
		}
	}
}

/* HandleCheckBlock handles CheckBlock requests which validates the sent block.
 * Valid blocks will be appended to host's blockchain.
 * host's chain will then be sent back to the sender. */
func HandleCheckBlock(request []byte) {
	var buff bytes.Buffer
	var payload CheckBlock

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	mutex.Lock()
	pow := NewProofOfWork(&payload.Block)

	if pow.Validate() {
		fmt.Println("Block is valid")

		Blockchain = append(Blockchain, payload.Block)
		spew.Dump(Blockchain)

	} else {
		fmt.Println("Block not valid")
	}
	mutex.Unlock()

	// Send Chain to sender
	SendChain(payload.AddrFrom)
}

/* SendHello sends hello requests for node discovery.
 * Neighbour is used when a new node does its first communication with a known node to request for their address list.
 * Ping is used to communicate to a node in peer's address list and waits for a pong.
 * Pong is used to confirm a ping to start getting a peer's chain. */
func SendHello(address, purpose string) {
	fmt.Printf("Sending hello %s to %s.\n", purpose, address)

	data := Hello{nodeAddress, purpose}
	payload := GobEncode(data)
	request := append(CmdToBytes("hello"), payload...)

	SendData(address, request)
}

/* SendAddr sends addr requests, sending the host's KnownNodes.  */
func SendAddr(address string) {
	fmt.Printf("Sending addr to %s.\n", address)

	data := Addr{nodeAddress, KnownNodes}
	payload := GobEncode(data)
	request := append(CmdToBytes("addr"), payload...)

	SendData(address, request)
}

/* SendGetChain sends getchain requests, asking the address for their blockchain. */
func SendGetChain(address string) {
	fmt.Printf("Sending getchain to %s.\n", address)

	data := GetChain{nodeAddress}
	payload := GobEncode(data)
	request := append(CmdToBytes("getchain"), payload...)

	SendData(address, request)
}

/* SendChain sends chain requests consisting of host's blockchain to address. */
func SendChain(address string) {
	fmt.Printf("Sending chain to %s.\n", address)

	data := Chain{nodeAddress, Blockchain}
	payload := GobEncode(data)
	request := append(CmdToBytes("chain"), payload...)

	SendData(address, request)
}

/* SendCheckBlock sends checkblock requests containing a newblock which is to be validated by address peer. */
func SendCheckBlock(address string, newBlock Block) {
	fmt.Printf("Sending checkblock to %s.\n", address)

	data := CheckBlock{nodeAddress, newBlock}
	payload := GobEncode(data)
	request := append(CmdToBytes("checkblock"), payload...)

	SendData(address, request)
}

/* SendData sends data to the address.
 * A connection to address is initiated. If an error occurs, address will be removed from KnownNodes. */
func SendData(address string, data []byte) {
	conn, err := net.Dial(protocol, address)

	if err != nil {
		fmt.Printf("%s is not available\n", address)
		var updatedNodes []string

		for _, node := range KnownNodes {
			if node != address {
				updatedNodes = append(updatedNodes, node)
			}
		}

		KnownNodes = updatedNodes

		return
	}

	defer conn.Close()

	_, err = io.Copy(conn, bytes.NewReader(data))
	if err != nil {
		log.Panic(err)
	}
}

/* RequestChain broadcasts GetChain request to peers. */
func RequestChain() {
	for _, node := range KnownNodes {
		if node != nodeAddress { 
			SendGetChain(node)
		}
	}
}

func RequestCheck(newBlock Block) {
	for _, address := range KnownNodes {
		if address != nodeAddress{
			SendCheckBlock(address, newBlock)
		}
	}
}

/* CmdToBytes converts a command string into a byte array of commandLength */
func CmdToBytes(cmd string) []byte {
	var bytes [commandLength]byte

	for i, c := range cmd {
		bytes[i] = byte(c)
	}

	return bytes[:]
}

/* BytesToCmd converts a byte array into a command string. */
func BytesToCmd(bytes []byte) string {
	var cmd []byte

	for _, b := range bytes {
		if b == 0x0 {
			break
		}

		cmd = append(cmd, b)
	}

	return fmt.Sprintf("%s", cmd)
}

/* GobEncode converts data into a byte array */
func GobEncode(data interface{}) []byte {
	var buff bytes.Buffer

	enc := gob.NewEncoder(&buff)
	err := enc.Encode(data)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}

/* NodeIsKnown checks the ip if it is in KnownNodes. */
func NodeIsKnown(ip string) bool {
	for _, node := range KnownNodes {
		if node == ip {
			return true
		}
	}

	return false
}

/************************
 * Blockchain Functions *
 ************************/

/* NewBlock generates and returns a Block */
func NewBlock(oldBlock Block, Data string) Block {

	var block Block

	t := time.Now()

	block.Index = oldBlock.Index + 1
	block.Timestamp = t.Format(layout)
	block.Data = Data
	block.PrevHash = oldBlock.Hash

	pow := NewProofOfWork(&block)
	nonce, hash := pow.RunPOW()

	block.Hash = hex.EncodeToString(hash[:])
	block.Nonce = nonce

	return block
}

/* StartBlockchain begins the Blockchain, appending a genesis Block */
func StartBlockchain() {
	t := time.Now()
	genesisBlock := Block{}
	genesisBlock = Block{0, t.Format(layout), "Genesis Block", "", "", 0}

	pow := NewProofOfWork(&genesisBlock)
	nonce, hash := pow.RunPOW()

	genesisBlock.Hash = hex.EncodeToString(hash[:])
	genesisBlock.Nonce = nonce

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

/* Validate validates block's Proof of Work
 *
 * Checks index, hash, prev hash.
 */
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int

	data := pow.prepareData(pow.block.Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])

	prevBlock := Blockchain[len(Blockchain)-1]

	if pow.block.Index != (prevBlock.Index + 1) {
		return false
	}

	if pow.block.PrevHash != prevBlock.Hash {
		return false
	}

	if hashInt.Cmp(pow.target) != -1 {
		return false
	}

	return true
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
	pflag.Parse()

	httpPort, _ = strconv.Atoi(fmt.Sprintf("%d", *httpPortFlag))
	mux := makeMuxRouter()
	log.Println(fmt.Sprintf("HTTP Server Listening on port :%d", httpPort))
	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", httpPort),
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
		Title string
		Data  string
		Port  string
	}{
		Title: "Blockchain Visualisation",
		Data:  strings.ReplaceAll(string(bytes), "\n", ""),
		Port:  strconv.Itoa(httpPort),
	}

	if err := tmpls.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

/* makeMuxRouter creates and return a router handler*/
func makeMuxRouter() http.Handler {
	muxRouter := mux.NewRouter()
	muxRouter.HandleFunc("/", handleWriteBlock).Methods("POST")
	muxRouter.HandleFunc("/web/", Index)
	muxRouter.PathPrefix("/web/").Handler(http.StripPrefix("/web/", http.FileServer(http.Dir("web/"))))
	return muxRouter
}

/* handleWriteBlock takes the JSON payload as data input and inserts a new block */
func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var msg Message
	var isValid bool

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&msg); err != nil {
		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
		return
	}
	defer r.Body.Close()

	prevBlock := Blockchain[len(Blockchain)-1]
	if msg.Data == "" {
		respondWithJSON(w, r, http.StatusBadRequest, r.Body)
		return
	}

	newBlock := NewBlock(prevBlock, msg.Data)

	// check if there are connected peers
	if len(KnownNodes) > 1 {
		go RequestCheck(newBlock)

		// set true to allow handleReceiveChain to send boolean to ValidChan
		jsonflag = true

		isValid = <-ValidChan

	} else {
		fmt.Println("No peers to send to, self-validating block.")

		mutex.Lock()
		pow := NewProofOfWork(&newBlock)

		if pow.Validate() {
			fmt.Println("Block is valid")

			Blockchain = append(Blockchain, newBlock)
			spew.Dump(Blockchain)

			isValid = true
		} else {
			fmt.Println("Block not valid")

			isValid = false
		}
		mutex.Unlock()

	}

	if isValid {
		respondWithJSON(w, r, http.StatusCreated, newBlock)
	}

	// set to false to prevent data sent to channel
	jsonflag = false
}

/* respondWithJSON writes a JSON text back to the web server */
func respondWithJSON(w http.ResponseWriter, r *http.Request, code int, payload interface{}) {
	response, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
