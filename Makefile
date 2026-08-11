.PHONY: all release release-shared-libs debug debug-shared-libs test clean

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

clean:
	rm -rf ./autark-cache