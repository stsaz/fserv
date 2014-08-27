#!/bin/sh

# extract debug data from a binary and put it in a separate file

for arg in "$@"; do
	objcopy --only-keep-debug $arg $arg.debug \
		&& strip --strip-debug $arg \
		&& objcopy --add-gnu-debuglink=$arg.debug $arg
done
