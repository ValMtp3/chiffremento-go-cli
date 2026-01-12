BINARY_NAME=chiffremento
VERSION=1.0.0
BUILD_DIR=build

.PHONY: all build build-all clean install test

all: test build

# Compile pour le système actuel
build:
	@echo "Building for current OS..."
	go build -ldflags="-s -w" -o $(BINARY_NAME) main.go

# Compile pour Linux, Mac (Intel/M1) et Windows
build-all: clean
	@echo "Building for all platforms..."
	mkdir -p $(BUILD_DIR)
	# Linux
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 main.go
	# macOS (Darwin)
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 main.go
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 main.go
	# Windows
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe main.go
	@echo "Done! Binaries are in $(BUILD_DIR)/"

# Nettoie les fichiers de build
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)

# Installe dans le $GOPATH/bin local
install:
	@echo "Installing globally with go install..."
	go install

# Lance les tests
test:
	go test ./pkg/...
