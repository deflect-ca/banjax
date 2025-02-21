#!/bin/bash

if [ -n "$ENABLE_AIR" ]; then
    exec air -c .air.toml
else
    exec ./banjax
fi
