BIN := ise2ise

.PHONY: build test dist clean

build:
	go build -o $(BIN) .

test:
	gofmt -l .
	go vet ./...
	go test ./...

dist:
	mkdir -p dist
	GOOS=darwin  GOARCH=arm64 go build -o dist/$(BIN)-darwin-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -o dist/$(BIN)-darwin-amd64 .
	GOOS=windows GOARCH=amd64 go build -o dist/$(BIN)-windows-amd64.exe .
	GOOS=linux   GOARCH=amd64 go build -o dist/$(BIN)-linux-amd64 .

clean:
	rm -rf dist $(BIN)
