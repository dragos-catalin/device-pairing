#!/usr/bin/env bash
# Build the cdylib, generate the Kotlin bindings, compile them with the JVM test
# using a downloaded kotlinc (no Gradle), and run it. Needs cargo, curl, unzip and a JDK (21).
# Usage: bash ffi/kotlin/run-tests.sh
set -euo pipefail

KOTLIN_VERSION=2.4.20
JNA_VERSION=5.19.1

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cache="$here/.cache"
generated="$here/generated"
mkdir -p "$cache"

kotlin_home="$cache/kotlinc-$KOTLIN_VERSION"
if [ ! -f "$kotlin_home/kotlinc/lib/kotlin-compiler.jar" ]; then
  echo "downloading kotlin-compiler $KOTLIN_VERSION"
  curl -fsSL -o "$cache/kotlin-compiler.zip" \
    "https://github.com/JetBrains/kotlin/releases/download/v$KOTLIN_VERSION/kotlin-compiler-$KOTLIN_VERSION.zip"
  rm -rf "$kotlin_home"
  unzip -q "$cache/kotlin-compiler.zip" -d "$kotlin_home"
  rm "$cache/kotlin-compiler.zip"
fi
jna="$cache/jna-$JNA_VERSION.jar"
if [ ! -f "$jna" ]; then
  echo "downloading jna $JNA_VERSION"
  curl -fsSL -o "$jna" "https://repo1.maven.org/maven2/net/java/dev/jna/jna/$JNA_VERSION/jna-$JNA_VERSION.jar"
fi

cd "$root"
cargo build -p device-pairing-ffi --release --locked
case "$(uname -s)" in
  Darwin) lib_name=libdevice_pairing_ffi.dylib ;;
  MINGW* | MSYS* | CYGWIN*) lib_name=device_pairing_ffi.dll ;;
  *) lib_name=libdevice_pairing_ffi.so ;;
esac
lib_dir="$root/target/release"
lib="$lib_dir/$lib_name"
rm -rf "$generated"
cargo run -q -p device-pairing-ffi --bin uniffi-bindgen --locked -- \
  generate --library "$lib" --language kotlin --out-dir "$generated" --no-format

jar="$cache/pairing-test.jar"
mapfile -t sources < <(find "$generated" "$here/test" -name '*.kt')
echo "kotlinc ${#sources[@]} files"
"$kotlin_home/kotlinc/bin/kotlinc" -nowarn -cp "$jna" "${sources[@]}" -include-runtime -d "$jar"

java "-Djna.library.path=$lib_dir" "-Duniffi.component.device_pairing.libraryOverride=$lib" \
  -cp "$jar:$jna" PairingTestKt
