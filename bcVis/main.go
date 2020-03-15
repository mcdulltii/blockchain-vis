package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/binary"
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
	"net"

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
}

// ProofOfWork represents a proof-of-work
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

type chatMessage struct {
	contents string
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
	Nonce int
	maxNonce = math.MaxInt64
	tmpls = template.Must(template.ParseFiles("web/index.html"))
	hostFlag    = pflag.IPP("host", "h", nil, "binding host")
	portFlag    = pflag.Uint16P("port", "p", 0, "binding port")
	addressFlag = pflag.StringP("address", "a", "", "publicly reachable network address")
)
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

	// Check if http port from .env file is used
	port := os.Getenv("PORT")
	ln, err := net.Listen("tcp", ":" + port)

	// Jump to End if http port is used (webserver is probably running)
	if err != nil {
		fmt.Printf("Webserver running on port %q\n", port)
		goto End
	}

	// Close tcp test connection
	err = ln.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't stop listening on port %q: %s\n", port, err)
		os.Exit(1)
	}

	go StartBlockchain()

	go func() {
		log.Fatal(run())
	}()

End:
	startChat()
}


/*****************
 * P2P Functions *
 *****************/

func startChat() {
	// Parse flags/options.
	pflag.Parse()

	// Create a new configured node.
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

	// Instantiate Kademlia.
	events := kademlia.Events{
		OnPeerAdmitted: func(id noise.ID) {
			fmt.Printf("Learned about a new peer %s(%s).\n", id.Address, id.ID.String()[:printedLength])
		},
		OnPeerEvicted: func(id noise.ID) {
			fmt.Printf("Forgotten a peer %s(%s).\n", id.Address, id.ID.String()[:printedLength])
		},
	}

	overlay := kademlia.New(kademlia.WithProtocolEvents(events))

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

func (m chatMessage) Marshal() []byte {
	return []byte(m.contents)
}

func unmarshalChatMessage(buf []byte) (chatMessage, error) {
	return chatMessage{contents: strings.ToValidUTF8(string(buf), "")}, nil
}

// check panics if err is not nil.
func check(err error) {
	if err != nil {
		panic(err)
	}
}

// printedLength is the total prefix length of a public key associated to a chat users ID.
const printedLength = 8

// input handles inputs from stdin.
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

// handle handles and prints out valid chat messages from peers.
func handle(ctx noise.HandlerContext) error {
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

	if len(msg.contents) == 0 {
		return nil
	}

	fmt.Printf("%s(%s)> %s\n", ctx.ID().Address, ctx.ID().ID.String()[:printedLength], msg.contents)

	return nil
}

// help prints out the users ID and commands available.
func help(node *noise.Node) {
	fmt.Printf("Your ID is %s(%s). Type '/discover' to attempt to discover new "+
		"peers, or '/peers' to list out all peers you are connected to.\n",
		node.ID().Address,
		node.ID().ID.String()[:printedLength],
	)
}

// bootstrap pings and dials an array of network addresses which we may interact with and  discover peers from.
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

// discover uses Kademlia to discover new peers from nodes we already are aware of.
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

// peers prints out all peers we are already aware of.
func peers(overlay *kademlia.Protocol) {
	ids := overlay.Table().Peers()

	var str []string
	for _, id := range ids {
		str = append(str, fmt.Sprintf("%s(%s)", id.Address, id.ID.String()[:printedLength]))
	}

	fmt.Printf("You know %d peer(s): [%v]\n", len(ids), strings.Join(str, ", "))
}

// chat handles sending chat messages and handling chat commands.
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

	for _, id := range overlay.Table().Peers() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := node.SendMessage(ctx, id.Address, chatMessage{contents: line})
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
