FROM golang

ADD . /go/src/blockchain-vis

WORKDIR /go/src/blockchain-vis

RUN go get -v -d ./...

RUN go build && \
	chmod 700 /go/src/blockchain-vis/b*

ENTRYPOINT ["bash"]

