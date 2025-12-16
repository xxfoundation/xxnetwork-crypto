.PHONY: update master release setup update_master update_release build clean wasm_tests tests

setup:
	git config --global --add url."git@gitlab.com:".insteadOf "https://gitlab.com/"

clean:
	rm -rf vendor/
	go mod vendor

update:
	-GOFLAGS="" go get -u all

build:
	go build ./...
	go mod tidy

update_release:
	GOFLAGS="" go get gitlab.com/xx_network/primitives@release
	GOFLAGS="" go get gitlab.com/elixxir/primitives@release
	GOFLAGS="" go get gitlab.com/xx_network/crypto@release

update_master:
	GOFLAGS="" go get gitlab.com/xx_network/primitives@master
	GOFLAGS="" go get gitlab.com/elixxir/primitives@master
	GOFLAGS="" go get gitlab.com/xx_network/crypto@master

master: update_master clean build

release: update_release clean build

wasm_tests:
	@echo "Running WASM tests (requires wasmbrowsertest)"
	@if ! command -v wasmbrowsertest >/dev/null 2>&1; then \
		echo "Error: wasmbrowsertest not found. Install with:"; \
		echo "  go install github.com/agnivade/wasmbrowsertest@latest"; \
		exit 1; \
	fi
	GOOS=js GOARCH=wasm go test -exec=$$(go env GOROOT)/lib/wasm/go_js_wasm_exec_browser -v ./...

tests: wasm_tests
