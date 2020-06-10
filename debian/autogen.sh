#!/bin/sh

set -eu

autoreconf -f -i -v -Wall
(cd pigeonhole && autoreconf -f -i -v -Wall)
