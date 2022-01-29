MODULE = github.com/binance-chain/tss-lib
PACKAGES = $(shell go list ./... | grep -v '/vendor/')

all: protob test

########################################
### Protocol Buffers

protob:
	@echo "--> Building Protocol Buffers"
	@for protocol in message signature ecdsa-keygen ecdsa-signing ecdsa-resharing eddsa-keygen eddsa-signing eddsa-resharing; do \
		echo "Generating $$protocol.pb.go" ; \
		protoc --go_out=. ./protob/$$protocol.proto ; \
	done

########################################
### Format

fmt:
	@go fmt ./...

lint:
	@golangci-lint run

build: protob
	go fmt ./...

########################################
### Benchmarking

benchgen: fmt
	cd cmd && go run ./tss-benchgen benchdata

benchsign: fmt
	cd cmd && go run ./tss-benchsign benchdata

########################################
### Testing

test_unit:
	@echo "--> Running Unit Tests"
	@echo "!!! WARNING: This will take a long time :)"
	go test -timeout 60m $(PACKAGES)

test_unit_race:
	@echo "--> Running Unit Tests (with Race Detection)"
	@echo "!!! WARNING: This will take a long time :)"
	# go clean -testcache
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
