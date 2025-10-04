BINARY=fastgate
PKG=./cmd/fastgate

all: build

build:
	CGO_ENABLED=0 go build -o bin/$(BINARY) $(PKG)

run:
	FASTGATE_CONFIG=${FASTGATE_CONFIG:-./config.example.yaml} go run $(PKG)

test:
	go test ./...

clean:
	rm -rf bin
