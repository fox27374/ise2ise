BIN := ise2ise

# What makes a release binary reproducible, so anyone can rebuild a tag and get
# the published SHA256 rather than having to trust the pipeline:
#
#   -trimpath      otherwise the absolute source path is baked in, and a build
#                  from /Users/you differs from the runner's /home/runner
#   CGO_ENABLED=0  a native darwin build links the host SDK and a cross build
#                  does not, so the same source produced two different binaries
#                  depending on where make ran
#
# The Go patch version is the third input; the release workflow pins it.
GOFLAGS_REPRO := -trimpath
export CGO_ENABLED = 0

.PHONY: build test dist clean

build:
	go build $(GOFLAGS_REPRO) -o $(BIN) .

test:
	gofmt -l .
	go vet ./...
	go test ./...

dist:
	mkdir -p dist
	GOOS=darwin  GOARCH=arm64 go build $(GOFLAGS_REPRO) -o dist/$(BIN)-darwin-arm64 .
	GOOS=darwin  GOARCH=amd64 go build $(GOFLAGS_REPRO) -o dist/$(BIN)-darwin-amd64 .
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS_REPRO) -o dist/$(BIN)-windows-amd64.exe .
	GOOS=linux   GOARCH=amd64 go build $(GOFLAGS_REPRO) -o dist/$(BIN)-linux-amd64 .

clean:
	rm -rf dist $(BIN)
