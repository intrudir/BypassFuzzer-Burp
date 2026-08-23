#!/usr/bin/env sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
jdk_root="$project_root/.gradle/jdks"
jdk_home="$jdk_root/temurin-17"

java_major() {
    output=$("$1" -version 2>&1 || true)
    version=$(printf '%s\n' "$output" | sed -n 's/.*version "\([0-9][0-9]*\).*/\1/p' | head -n 1)
    [ -n "$version" ] && [ "$version" -ge 17 ] 2>/dev/null
}

find_java() {
    candidates=""
    [ -x "$jdk_home/bin/java" ] && candidates="$candidates:$jdk_home/bin/java"
    [ -n "${JAVA_HOME:-}" ] && candidates="$candidates:$JAVA_HOME/bin/java"
    command -v java >/dev/null 2>&1 && candidates="$candidates:$(command -v java)"
    for home in /usr/lib/jvm/* /Library/Java/JavaVirtualMachines/*/Contents/Home; do
        [ -x "$home/bin/java" ] && candidates="$candidates:$home/bin/java"
    done
    old_ifs=$IFS
    IFS=:
    for candidate in $candidates; do
        [ -x "$candidate" ] && java_major "$candidate" && { printf '%s\n' "$candidate"; IFS=$old_ifs; return 0; }
    done
    IFS=$old_ifs
    return 1
}

install_java() {
    case "$(uname -s)" in
        Darwin) os=mac; extension=tar.gz ;;
        Linux) os=linux; extension=tar.gz ;;
        *) echo 'Unsupported OS. Run build.ps1 on Windows or install Java 17+ and invoke Gradle directly.' >&2; exit 1 ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) arch=x64 ;;
        arm64|aarch64) arch=aarch64 ;;
        *) echo "Unsupported CPU architecture: $(uname -m)" >&2; exit 1 ;;
    esac
    archive="${TMPDIR:-/tmp}/bypassfuzzer-temurin-17.tar.gz"
    extract_root="$jdk_root/download-$$"
    mkdir -p "$jdk_root"
    url="https://api.adoptium.net/v3/binary/latest/17/ga/$os/$arch/jdk/hotspot/normal/eclipse"
    echo 'No Java 17+ installation found; downloading Temurin 17 for this project...' >&2
    if command -v curl >/dev/null 2>&1; then curl --fail --location --silent --show-error --max-time 120 "$url" -o "$archive"; else wget -q --timeout=120 "$url" -O "$archive"; fi
    mkdir -p "$extract_root"
    tar -xzf "$archive" -C "$extract_root"
    found_home=$(find "$extract_root" -mindepth 1 -maxdepth 1 -type d | head -n 1)
    [ -n "$found_home" ] || { echo 'The Java download did not contain a JDK directory.' >&2; exit 1; }
    rm -rf "$jdk_home"
    mv "$found_home" "$jdk_home"
    rm -rf "$extract_root" "$archive"
    printf '%s\n' "$jdk_home/bin/java"
}

if java=$(find_java); then
    :
else
    java=$(install_java)
fi
export JAVA_HOME=$(CDPATH= cd -- "$(dirname -- "$(dirname -- "$java")")" && pwd)
if [ "$#" -eq 0 ]; then
    set -- clean build
fi
exec "$project_root/gradlew" "$@"
