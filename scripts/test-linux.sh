#!/bin/sh
set -eu

docker run --rm --privileged \
	-v /Users/k.majdoub/repos/ghostrun:/src \
	-w /src \
	golang:latest \
	sh -lc 'export PATH=/usr/local/go/bin:$PATH; GHOSTRUN_INTEGRATION=1 go test ./...'
