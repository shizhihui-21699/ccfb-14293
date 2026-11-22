#!/usr/bin/env bash
# 零依赖构建：仅需 JDK 17+（本仓库在 JDK 21 上验证）。
# 用法: ./build.sh           编译并运行全部测试
#       ./build.sh compile   仅编译
set -euo pipefail

# 允许通过 JAVA_HOME 或自动发现 Homebrew OpenJDK
if [[ -z "${JAVA_HOME:-}" ]]; then
  for candidate in \
    /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
    /opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home \
    /usr/lib/jvm/default-java ; do
    if [[ -x "$candidate/bin/javac" ]]; then
      export JAVA_HOME="$candidate"
      break
    fi
  done
fi
if [[ -z "${JAVA_HOME:-}" || ! -x "$JAVA_HOME/bin/javac" ]]; then
  echo "ERROR: JDK not found. Set JAVA_HOME to a JDK 17+ installation." >&2
  exit 2
fi
echo "Using JAVA_HOME=$JAVA_HOME"
"$JAVA_HOME/bin/java" -version

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/src"
OUT="$ROOT/out"
rm -rf "$OUT"
mkdir -p "$OUT"

echo "== Compiling =="
find "$SRC" -name '*.java' > "$OUT/sources.txt"
"$JAVA_HOME/bin/javac" -encoding UTF-8 -d "$OUT" @"$OUT/sources.txt"

if [[ "${1:-all}" == "compile" ]]; then
  echo "Compiled classes in $OUT"
  exit 0
fi

echo "== Running tests =="
"$JAVA_HOME/bin/java" -cp "$OUT" com.atm.tests.TestRunner

if [[ "${1:-all}" == "demo" ]]; then
  echo "== Running attack demo =="
  "$JAVA_HOME/bin/java" -cp "$OUT" com.atm.demo.AttackDemo
fi
