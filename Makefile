.PHONY: all release release-shared-libs debug debug-shared-libs test test-release clean compile-commands sources

all: release;

release:
	BUILD_TYPE=Release ./build.sh

release-shared-libs:
	BUILD_TYPE=Release IOWOW_BUILD_SHARED_LIBS=1 ./build.sh

debug:
	BUILD_TYPE=Debug ./build.sh

debug-shared-libs:
	BUILD_TYPE=Debug IOWOW_BUILD_SHARED_LIBS=1 ./build.sh

test:
	BUILD_TYPE=Debug IOWOW_RUN_TESTS=1 ./build.sh

test-release:
	BUILD_TYPE=Release IOWOW_RUN_TESTS=1 ./build.sh

compile-commands:
	IOWOW_BUILD_TESTS=1 BUILD_TYPE=Debug  ./build.sh -k
	cp ./autark-cache/compile_commands.json ./compile_commands.json

sources:
	@tmp_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp_dir"' EXIT; \
	./build.sh --prefix="$$tmp_dir" -S; \
	base_dir="$$tmp_dir/share/iowow"; \
	src_dir="$$(find "$$base_dir" -mindepth 1 -maxdepth 1 -type d -print -quit)"; \
	name="$$(basename "$$src_dir")"; \
	tar -C "$$base_dir" -czf "$(CURDIR)/$$name.tar.gz" "$$name"; \
	echo "Created: $(CURDIR)/$$name.tar.gz"

clean:
	rm -rf ./autark-cache