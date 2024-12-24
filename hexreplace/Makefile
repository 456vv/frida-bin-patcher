.PHONY: test build

help:
	@echo "make test - Run the tests"
	@echo "make build - Build the project"

build:
	@go build -trimpath -ldflags="-s -w"

test:
	@go run main.go -seed 1659 -length 5