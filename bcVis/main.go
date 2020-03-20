package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/binary"
	"encoding/gob"
	"io"
	"log"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"math"
	"math/big"
	"strings"
	"sync"
	"time"
	"bufio"
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/perlin-network/noise"
	"github.com/perlin-network/noise/kademlia"
	"github.com/spf13/pflag"
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
	Nonce 	  int
}

// ProofOfWork represents a proof-of-work
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// chatMessage is the struct that is sent to peers
type chatMessage struct {
	Request []byte
}


// Message takes incoming JSON payload for writing heart rate
type Message struct {
	Data string
}


/*************
 * Variables *
 *************/

var (
	Blockchain []Block
	mutex = &sync.Mutex{}
	maxNonce = math.MaxInt64
	ValidChan = make(chan bool)
	jsonflag = false
	tmpls = template.Must(template.ParseFiles("web/index.html"))
	hostFlag    = pflag.IPP("host", "h", nil, "binding host")
	portFlag    = pflag.Uint16P("port", "p", 0, "binding port")
	addressFlag = pflag.StringP("address", "a", "", "publicly reachable network address")
	httpPortFlag = pflag.IntP("webport", "w", loadenv(), "web server port")

	node noise.Node

	// Instantiate Kademlia.
	events = kademlia.Events{
		OnPeerAdmitted: func(id noise.ID) {
			fmt.Printf("Learned about a new peer %s(%s).\n", id.Address, id.ID.String()[:printedLength])
		},
		OnPeerEvicted: func(id noise.ID) {
			fmt.Printf("Forgotten a peer %s(%s).\n", id.Address, id.ID.String()[:printedLength])
		},
	}

	overlay = kademlia.New(kademlia.WithProtocolEvents(events))
)

const (
	targetBits = 15 // difficulty setting
	printedLength = 8 // printedLength is the total prefix length of a public key associated to a chat users ID.
	commandLength = 12
	layout = "2006-01-02 15:04:05"
)


/*************
 * Functions *
 *************/

func main() {
	pflag.Parse()

	go StartBlockchain()

	go startChat()

	func() {
		log.Fatal(run())
	}()
}


/*****************
 * P2P Functions *
 *****************/

/* startChat is the main running function enabling peer to peer (p2p) functionalities.
 * 
 * incoming communications are done by handle
 * outgoing communications are done by the respective send functions (sendGetChain, sendReceiveChain, sendCheckBlock and chat)
 */
func startChat() {
	// configure new node
	node, err := noise.NewNode(
		noise.WithNodeBindHost(*hostFlag),
		noise.WithNodeBindPort(*portFlag),
		noise.WithNodeAddress(*addressFlag),
	)
	check(err)

	// Release resources associated to node at the end of the program.
	defer node.Close()

	// Register the chatMessage Go type to the node with an associated unmarshal function.
	node.RegisterMessage(chatMessage{}, unmarshalChatMessage)

	// Register a message handler to the node.
	node.Handle(handle)

	// Bind Kademlia to the node.
	node.Bind(overlay.Protocol())

	// Have the node start listening for new peers.
	check(node.Listen())

	// Print out the nodes ID and a help message comprised of commands.
	help(node)

	// Ping nodes to initially bootstrap and discover peers from.
	bootstrap(node, pflag.Args()...)

	// Attempt to discover peers if we are bootstrapped to any nodes.
	discover(overlay)

	// Accept chat message inputs and handle chat commands in a separate goroutine.
	go input(func(line string) {
		chat(node, overlay, line)
	})

	// Wait until Ctrl+C or a termination call is done.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	// Close stdin to kill the input goroutine.
	check(os.Stdin.Close())

	// Empty println.
	println()
}

/* Marshal used to convert data within chatMessage to a byte array */
func (m chatMessage) Marshal() []byte {
	return m.Request
}

/* unmarshalChatMessage returns a chatMessage struct with Request byte array */
func unmarshalChatMessage(buf []byte) (chatMessage, error) {
	return chatMessage{Request: buf}, nil
}

/* check panics if err is not nil. */
func check(err error) {
	if err != nil {
		panic(err)
	}
}

/* input handles inputs from stdin. 
 * this function works alongside chat
 */
func input(callback func(string)) {
	r := bufio.NewReader(os.Stdin)

	for {
		buf, _, err := r.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}

			check(err)
		}

		line := string(buf)
		if len(line) == 0 {
			continue
		}

		callback(line)
	}
}

/* sendGetChain generates a request for peers' blockchain. */
func SendGetChain(overlay *kademlia.Protocol) {
	fmt.Println("Sending GetChain to peers.")
	ids := overlay.Table().Peers()

	if len(ids) > 0 {
		nodeAddr := node.ID().Address

		payload := GobEncode(nodeAddr)
		request := append(CmdToBytes("GetChain"), payload...)

		for _, id := range ids {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err := node.SendMessage(ctx, id.Address, chatMessage{Request: request})
			cancel()

			if err != nil {
				fmt.Printf("Failed to send message to %s(%s). Skipping... [error: %s]\n",
					id.Address,
					id.ID.String()[:printedLength],
					err,
				)
				continue
			}	
		}	
	} else {
		fmt.Println("No peers to send to.")
	}
}

/* sendReceiveChain generates a response to send its blockchain to a peer. 
 * 
 * this function will be called by handleGetChain and handleCheckBlock
 */
func SendReceiveChain(ctx noise.HandlerContext) {
	fmt.Printf("Sending chain to %s\n", ctx.ID().Address)
	byteChain := GobEncode(Blockchain)
	newRequest := append(CmdToBytes("ReceiveChain"), byteChain...)

	sendAddr, sendID := ctx.ID().Address, ctx.ID().ID.String()[:printedLength]

	newCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	err := node.SendMessage(newCtx, sendAddr, chatMessage{Request: newRequest})
	cancel()

	if err != nil {
		fmt.Printf("Failed to send message to %s(%s). Skipping... [error: %s]\n",
			sendAddr,
			sendID,
			err,
		)
	}
}

/* sendCheckBlock generates a request to send a block for validation to all peers. */
func SendCheckBlock(newBlock Block, overlay *kademlia.Protocol) {
	fmt.Println("Sending CheckBlock to peers.")
	ids := overlay.Table().Peers()

	if len(ids) > 0 {
		payload := GobEncode(newBlock)
		request := append(CmdToBytes("CheckBlock"), payload...)

		for _, id := range ids {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err := node.SendMessage(ctx, id.Address, chatMessage{Request: request})
			cancel()

			if err != nil {
				fmt.Printf("Failed to send message to %s(%s). Skipping... [error: %s]\n",
					id.Address,
					id.ID.String()[:printedLength],
					err,
				)
				continue
			}
		}
	} else {
		fmt.Println("No peers to send to")
	}
}

/* handleStdin handles the request sent from terminal line */
func handleStdin(request []byte, ctx noise.HandlerContext) error {
	var buff bytes.Buffer
	var payload string

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	if len(payload) == 0 {
			return nil
	}

	fmt.Printf("%s(%s)> %s\n", ctx.ID().Address, ctx.ID().ID.String()[:printedLength], payload)

	return nil
}

/* handleGetChain handles the GetChain request. It will send a ReceiveChain request to the sender */
func handleGetChain(request []byte, ctx noise.HandlerContext) error {
	var buff bytes.Buffer
	var payload string

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	if len(payload) == 0 {
			return nil
	}

	fmt.Printf("GetChain request from %s\n", payload)

	// prepare request to send chain
	SendReceiveChain(ctx)

	return nil
}

/* handleReceiveChain handles ReceiveChain requests. It will append chains which are longer or have an earlier genesis block.
 * It will also send a boolean data to ValidChan to update the web server.
 */
func handleReceiveChain(request []byte, ctx noise.HandlerContext) error {
	var buff bytes.Buffer
	var payload []Block

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	fmt.Printf("Received chain from %s(%s)\n", ctx.ID().Address, ctx.ID().ID.String()[:printedLength])

	// replace BlockChain if payload chain is longer
	if len(payload) > len(Blockchain) {
		fmt.Println("Longer chain detected, replacing current chain")

		Blockchain = payload
		spew.Dump(Blockchain)

		if jsonflag {
			ValidChan <- true
		}

	} else if len(payload) == len(Blockchain) && len(payload) == 1 {
		t1, _ := time.Parse(layout, payload[0].Timestamp)
		t2, _ := time.Parse(layout, Blockchain[0].Timestamp)

		if t1.Before(t2) {
			fmt.Println("Received genesis block is earlier, replace chain")

			Blockchain = payload
			spew.Dump(Blockchain)

		} else {
			fmt.Println("Discarded new chain")
		}

	} else {
		fmt.Println("Discarded new chain")

		if jsonflag {
			ValidChan <- false
		}
	}

	return nil
}

/* handleCheckBlock handles CheckBlock requests. It receives a block from a peer and validates it 
 * and sends its own chain to the peer afterwards.
 */
func handleCheckBlock(request []byte, ctx noise.HandlerContext) error {
	var buff bytes.Buffer
	var payload Block

	buff.Write(request[commandLength:])
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}

	fmt.Printf("Received block from %s(%s)\n", ctx.ID().Address, ctx.ID().ID.String()[:printedLength])

	mutex.Lock()
	pow := NewProofOfWork(&payload)

	if pow.Validate() {
		fmt.Println("Block is valid")

		Blockchain = append(Blockchain, payload)
		spew.Dump(Blockchain)

	} else {
		fmt.Println("Block not valid")
	}
	mutex.Unlock()

	// relay current blockchain back to the PC that generated the block
	SendReceiveChain(ctx)

	return nil

}

/* CmdToBytes converts a command string into a byte array of commandLength */
func CmdToBytes(cmd string) []byte {
	var bytes [commandLength]byte

	for i, c := range cmd {
		bytes[i] = byte(c)
	}

	return bytes[:]
}

/* BytesToCmd converts a byte array into a command string */
func BytesToCmd(bytes []byte) string {
	var cmd []byte

	for _, b := range bytes {
		if b != 0x0 {
			cmd = append(cmd, b)
		}
	}

	return fmt.Sprintf("%s", cmd)
}

/* GodEncode converts data into a byte array */
func GobEncode(data interface{}) []byte {
	var buff bytes.Buffer

	enc := gob.NewEncoder(&buff)
	err := enc.Encode(data)
	if err != nil {
		log.Panic(err)
	}

	return buff.Bytes()
}

/* handle is the main handler for the peer to peer functionalities. It will decode the commmand header
 * and call the respective command handler 
 */
func handle (ctx noise.HandlerContext) error {
	if ctx.IsRequest() {
		return nil
	}

	obj, err := ctx.DecodeMessage()
	if err != nil {
		return nil
	}

	msg, ok := obj.(chatMessage)
	if !ok {
		return nil
	}

	req := msg.Request

	command := BytesToCmd(req[:commandLength])
	fmt.Printf("Received %s command\n", command)

	switch command {
	case "Stdin":
		return handleStdin(req, ctx)
	
	case "GetChain":
		return handleGetChain(req, ctx)

	case "ReceiveChain":
		return handleReceiveChain(req, ctx)

	case "CheckBlock":
		return handleCheckBlock(req, ctx)
	} 
	return nil
}

/* help prints out the users ID and commands available. */
func help(node *noise.Node) {
	fmt.Printf("Your ID is %s(%s). Type '/discover' to attempt to discover new "+
		"peers, or '/peers' to list out all peers you are connected to.\n",
		node.ID().Address,
		node.ID().ID.String()[:printedLength],
	)
}

/* bootstrap pings and dials an array of network addresses which we may interact with and  discover peers from. */
func bootstrap(node *noise.Node, addresses ...string) {
	for _, addr := range addresses {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := node.Ping(ctx, addr)
		cancel()

		if err != nil {
			fmt.Printf("Failed to ping bootstrap node (%s). Skipping... [error: %s]\n", addr, err)
			continue
		}
	}
}

/* discover uses Kademlia to discover new peers from nodes we already are aware of. */
func discover(overlay *kademlia.Protocol) {
	ids := overlay.Discover()

	var str []string
	for _, id := range ids {
		str = append(str, fmt.Sprintf("%s(%s)", id.Address, id.ID.String()[:printedLength]))
	}

	if len(ids) > 0 {
		fmt.Printf("Discovered %d peer(s): [%v]\n", len(ids), strings.Join(str, ", "))
	} else {
		fmt.Printf("Did not discover any peers.\n")
	}
}

/* peers prints out all peers we are already aware of. */
func peers(overlay *kademlia.Protocol) {
	ids := overlay.Table().Peers()

	var str []string
	for _, id := range ids {
		str = append(str, fmt.Sprintf("%s(%s)", id.Address, id.ID.String()[:printedLength]))
	}

	fmt.Printf("You know %d peer(s): [%v]\n", len(ids), strings.Join(str, ", "))
}

/* chat handles sending chat messages and handling chat commands. */
func chat(node *noise.Node, overlay *kademlia.Protocol, line string) {
	switch line {
	case "/discover":
		discover(overlay)
		return
	case "/peers":
		peers(overlay)
		return
	default:
	}

	if strings.HasPrefix(line, "/") {
		help(node)
		return
	}


	payload := GobEncode(line)
	request := append(CmdToBytes("Stdin"), payload...)

	for _, id := range overlay.Table().Peers() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := node.SendMessage(ctx, id.Address, chatMessage{Request: request})
		cancel()

		if err != nil {
			fmt.Printf("Failed to send message to %s(%s). Skipping... [error: %s]\n",
				id.Address,
				id.ID.String()[:printedLength],
				err,
			)
			continue
		}
	}
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

	// Send GetChain request to peers
	SendGetChain(overlay)
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

	prevBlock := Blockchain[len(Blockchain) - 1]

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
func loadenv() int {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	// Check if http port from .env file is used
	port, err := strconv.Atoi(os.Getenv("PORT"))

	return port
}

 /* run will set up a http server */
func run() error {
	mux := makeMuxRouter()
	log.Println(fmt.Sprintf("HTTP Server Listening on port :%d", *httpPortFlag))
	s := &http.Server{
		Addr:           fmt.Sprintf(":%d", *httpPortFlag),
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
		Data  string
		Port  string
	}{
		Title:  "Blockchain Visualisation",
		Data:  strings.ReplaceAll(string(bytes), "\n", ""),
		Port:  strconv.Itoa(*httpPortFlag),
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
	if len(overlay.Table().Peers()) > 0 {
		// Broadcast new block to peers
		go SendCheckBlock(newBlock, overlay)

		// set true to allow handleReceiveChain to send boolean to ValidChan
		jsonflag = true

		isValid = <- ValidChan

	} else {
		fmt.Println("no peers to send to, self-validating block.")

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
