.PHONY: test-build
test-build:
	docker build -t furui-test -f Dockerfile.tests .

.PHONY: test-up
test-up:
	docker-compose -f tests/build/docker-compose.yml up -d

.PHONY: test-down
test-down:
	docker-compose -f tests/build/docker-compose.yml down

.PHONY: test
test:
	go test -v ./... -count=1 -cover

.PHONY: test-short
test-short:
	go test --short -v ./... -count=1 -cover

.PHONY: format
format:
	clang-format -i $(wildcard usecase/ebpf/*.c)
	go fmt ./...

.PHONY: lint
lint:
	clang-format --dry-run --Werror $(wildcard usecase/ebpf/*.c)
	go vet -vettool=`which checkspaces` ./...
	golangci-lint run --out-format=github-actions --enable=staticcheck,stylecheck,gosimple,gosec,prealloc,gocognit,bodyclose,gofmt
