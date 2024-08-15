#!/bin/bash -Cex

for file in ~/src/llvm-project/llvm/test/CodeGen/SyncVM/*.ll; do
  ~/opt/llvm/bin/llc "${file}" -o "examples/$(basename ${file} .ll).sasm"
done
