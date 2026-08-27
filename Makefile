.PHONY: build clean run test vet help

# Go environment (workaround for D:\go permission issues)
export GOTOOLCHAIN=local
export GOSUMDB=off
export GOCACHE=$(HOME)/.cache/go-build
export GOPATH=$(HOME)/go

BINARY=gosleek
MAIN=./cmd/gosleek

build:
	go build -o $(BINARY).exe $(MAIN)

run: build
	./$(BINARY).exe $(ARGS)

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY).exe

help:
	@echo "gosleek - template-driven vulnerability scanner"
	@echo ""
	@echo "Make targets:"
	@echo "  build  - Compile the binary"
	@echo "  run    - Build and run (use ARGS='scan -t http://example.com')"
	@echo "  test   - Run tests"
	@echo "  vet    - Static analysis"
	@echo "  clean  - Remove build artifacts"
