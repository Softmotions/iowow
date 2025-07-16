.PHONY: all release debug test clean

all: release;

release:
	BUILD_TYPE=Release ./build.sh

debug:
	BUILD_TYPE=Debug ./build.sh

test:
	BUILD_TYPE=Debug IOWOW_RUN_TESTS=1 ./build.sh

test-release:
	BUILD_TYPE=Release IOWOW_RUN_TESTS=1 ./build.sh

clean:
	rm -rf ./autark-cache