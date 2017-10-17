FROM golang:1.9
RUN go get -v github.com/golang/dep/cmd/dep && \
    go get -v golang.org/x/tools/cmd/... && \
    go get -v github.com/alecthomas/gometalinter && \
    gometalinter --install && \
    chmod -R a+rw /go
