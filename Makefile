BINARY_NAME=chiffremento
BUILD_DIR=build

# La version vient de git, pas d'une constante à mettre à jour à la main.
# Elle est injectée dans le binaire : sans -X, `chiffremento -version`
# répondait « dev » même après un make build.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS=-s -w -X main.version=$(VERSION)

.PHONY: all build build-all clean install test lint

all: lint test build

# Compile pour le système actuel
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) .

# Compile pour Linux, macOS (Intel/ARM) et Windows
build-all: clean
	@echo "Building $(VERSION) for all platforms..."
	mkdir -p $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Done! Binaries are in $(BUILD_DIR)/"

# Nettoie les fichiers de build
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)

# Installe dans le $GOPATH/bin local
install:
	go install -ldflags="$(LDFLAGS)" .

# Mêmes contrôles que la CI
lint:
	@test -z "$$(gofmt -l .)" || (echo "fichiers non formatés :"; gofmt -l .; exit 1)
	go vet ./...

# Lance les tests
test:
	go test -race ./...
