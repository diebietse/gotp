test:
	go test ./... -cover -race -mod=vendor -v
.PHONY: test

vendor:
	go mod tidy
	go mod vendor
.PHONY: vendor

gofmt:
	gofmt -l -s -w .
.PHONY: gofmt

