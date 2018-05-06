# Cross compilation

## Prerequisites

```sh
  sudo apt-get install bison flex libtool ruby scons intltool libtool-bin p7zip-full wine
```

## Build


### Prepare MXE 

```sh
git submodule update --init
```

`nano ./mxr/settings.mk`:

```
JOBS := 1
MXE_TARGETS := x86_64-w64-mingw32.static
LOCAL_PKG_LIST := cunit libiberty	
.DEFAULT local-pkg-list:
local-pkg-list: $(LOCAL_PKG_LIST)
```

```
cd ./mxe
make
```

### Cross compilation

```
mkdir ./build
cd  ./build

export MXE_HOME=<path to project>/mxe

cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_TOOLCHAIN_FILE=../win64-tc.cmake \
         -DBUILD_TESTS=OFF -DTEST_TOOL_CMD=wine

make package         
```
