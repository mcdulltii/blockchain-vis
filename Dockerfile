FROM golang

ADD . /go/src/blockchain-vis

RUN cd src/blockchain-vis/bcVis && \
	go build && \
	chmod 700 /go/src/blockchain-vis/bcVis/b*

WORKDIR /go/src/blockchain-vis/bcVis

ENTRYPOINT ["bash"]

