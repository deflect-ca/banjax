#!/bin/bash

if [ -n "$ENABLE_AIR" ]; then
    air -c .air.toml
else
    ./banjax
fi

