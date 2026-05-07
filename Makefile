.PHONY: build install package-deb package-arch package-tar checksums release test clean

build:
	mkdir -p build
	cargo build --manifest-path engine/Cargo.toml --release
	go build -o build/netscope ./cmd/netscope
	cp engine/target/release/netscope-engine build/

install: build
	sh scripts/install.sh

package-deb: build
	sh scripts/package-deb.sh

package-arch:
	sh scripts/package-arch.sh

package-tar: build
	sh scripts/release-tarball.sh

checksums:
	sh scripts/checksums.sh

release: build package-tar package-deb checksums

test:
	cargo test --manifest-path engine/Cargo.toml
	go test ./...

clean:
	cargo clean --manifest-path engine/Cargo.toml
	rm -rf build dist
