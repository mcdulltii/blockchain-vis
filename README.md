# Blockchain Visualization
P5JS Visualization for Golang Blockchain

## Usage
1. <strong>Docker</strong>
```shell
make    # To build docker image
```
Using two terminals, exec "make run*" to access bash on built docker images
- Terminal 1
```shell
admin$ make run1
# Access bash on bc-docker image with exposed ports 4444 and 8000
bc-docker$ ./bcVis -p 4444
```
- Terminal 2
```shell
admin$ make run2
# Access bash on bc-docker image with exposed ports 4445 and 8001
bc-docker$ ./bcVis -p 4445 -w 8001 (ip_of_terminal_1):4444
```

2. <strong>Manual</strong>
```shell
cd bcVis
go build
```
- Terminal 1
```shell
./bcVis -p 4444
```
- Terminal 2
```shell
./bcVis -p 4445 -w 8001 (ip_of_terminal_1):4444
```

## P5JS Web Visualizations
Default .env port: <b>8000</b>

Access web server through http://localhost:(port)/web/

## Adding to Blockchain
- cURL
```shell
curl -d '{"Data":"(transaction_data)"}' http://(ip):(port)/
```
- Web Server
  - Posts using textbox input  <i>(localhost only)</i>
  - Reloads if POST response is invalid