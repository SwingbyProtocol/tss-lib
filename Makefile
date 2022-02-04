MODULE = github.com/binance-chain/tss-lib
PACKAGES = $(shell go list ./... | grep -v '/vendor/')
UT_TIMEOUT = -timeout 60m
UT_COVER = -covermode=atomic -cover
UT_PACKAGES_LEVEL_0 = $(shell go list ./... | grep -v '/vendor/' | grep 'keygen' )
UT_PACKAGES_LEVEL_1 = $(shell go list ./... | grep -v '/vendor/' | grep -v 'keygen'  )

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

test_unit_level0:
	@echo "--> Running Unit Tests - Level 0"
	@echo "!!! WARNING: This will take a long time :)"
	@echo "!!! WARNING: This will delete fixtures  :("
	go clean -testcache
	rm -f ./test/_ecdsa_fixtures/*json
	rm -f ./test/_eddsa_fixtures/*json
	go test ${UT_TIMEOUT} ${UT_COVER} $(UT_PACKAGES_LEVEL_0)


test_unit: test_unit_level0
	@echo "--> Running Unit Tests - Level 1"
	@echo "!!! WARNING: This will take a long time :)"
	go test ${UT_TIMEOUT} ${UT_COVER} $(UT_PACKAGES_LEVEL_1)

test_unit_race_level0:
	@echo "--> Running Unit Tests (with Race Detection) - Level 0"
	@echo "!!! WARNING: This will take a long time :)"
	@echo "!!! WARNING: This will delete fixtures :("
	go clean -testcache
	rm -f ./test/_ecdsa_fixtures/*json
	rm -f ./test/_eddsa_fixtures/*json
	go test -race ${UT_TIMEOUT} ${UT_COVER} $(UT_PACKAGES_LEVEL_0)

test_unit_race: test_unit_race_level0
	@echo "--> Running Unit Tests (with Race Detection) - Level 1"
	@echo "!!! WARNING: This will take a long time :)"
	go test -race ${UT_TIMEOUT} ${UT_COVER} $(UT_PACKAGES_LEVEL_1)

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
