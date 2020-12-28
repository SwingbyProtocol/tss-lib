MODULE = github.com/binance-chain/tss-lib
PACKAGES = $(shell go list ./... | grep -v '/vendor/')
ENTRYPOINT = ./cmd/...
LD_FLAGS = -s -w
BUILD_FLAGS = -trimpath -ldflags "$(LD_FLAGS)"
BUILD_OUT = ./build/

all: protob test

########################################
### Protocol Buffers

protob:
	@echo "--> Building Protocol Buffers"
	@for file in shared message ecdsa-keygen ecdsa-signing ecdsa-signature ecdsa-resharing eddsa-keygen eddsa-signing eddsa-signature eddsa-resharing; do \
		echo "Generating $$file.pb.go" ; \
		protoc --go_out=module=$(MODULE):. ./protob/$$file.proto ; \
	done

########################################
### Format

fmt:
	@go fmt ./...

lint:
	@golangci-lint run

########################################
### Build

build: fmt
	@echo "--> Building bench tools"
	mkdir -p ./build
	go build ${BUILD_FLAGS} -o ${BUILD_OUT} ${ENTRYPOINT}
	@echo "\n--> Build complete"

########################################
### Benchmarking

benchgen: fmt
	go run ./cmd/tss-benchgen benchdata

benchsign: fmt
	go run ./cmd/tss-benchsign benchdata

########################################
### Testing

test_unit:
	@echo "--> Running Unit Tests"
	@echo "!!! WARNING: This will take a long time :)"
	go test -timeout 60m $(PACKAGES)

test_unit_race:
	@echo "--> Running Unit Tests (with Race Detection)"
	@echo "!!! WARNING: This will take a long time :)"
	go test -timeout 60m -race $(PACKAGES)

test:
	make test_unit_race

########################################
### Pre Commit

pre_commit: build test

########################################

# To avoid unintended conflicts with file names, always add to .PHONY
# # unless there is a reason not to.
# # https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: protob build test_unit test_unit_race test benchgen benchsign
