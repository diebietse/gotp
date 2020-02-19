test:
	go test -mod=vendor -v -race -coverprofile=coverage.txt -covermode=atomic ./...
.PHONY: test

vendor:
	go mod tidy
	go mod vendor
.PHONY: vendor

gofmt:
	gofmt -l -s -w ./*.go
.PHONY: gofmt

benchmark:
	go test -benchmem -bench .
.PHONY: benchmark