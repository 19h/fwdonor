#!/bin/bash
# Build libtdjson.so into tdlib/lib/ (adapted from decidot's build-tdlib.sh,
# pinned to the same TDLib revision). Needs cmake, ninja, gperf, a C++
# compiler and the zlib/OpenSSL headers. Set TDLIB_BUILD_JOBS on hosts with
# little free memory: some TDLib units need several GB each to compile.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
revision=c15d3f5a5de6e3ba5839822c451152e5e18bb700
if [ ! -d tdlib-source/.git ]; then
  git clone https://github.com/tdlib/td.git tdlib-source
fi
git -C tdlib-source fetch --quiet origin || true
git -C tdlib-source checkout --quiet "$revision"
cmake -S tdlib-source -B tdlib-build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DTD_ENABLE_LTO=OFF
cmake --build tdlib-build --target tdjson -j "${TDLIB_BUILD_JOBS:-4}"
install -d tdlib/lib
install -m 755 "$(readlink -f tdlib-build/libtdjson.so)" tdlib/lib/libtdjson.so
cp tdlib-source/LICENSE_1_0.txt tdlib/LICENSE_1_0.txt
printf '%s\n' "$revision" > tdlib/REVISION
echo "installed tdlib/lib/libtdjson.so ($(du -h tdlib/lib/libtdjson.so | cut -f1))"
