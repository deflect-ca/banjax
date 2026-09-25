# Copyright (c) 2026, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# One-off tool for sending a simulated banjax kafka command message. Built
# from the repo root so it shares the main module's go.mod/go.sum instead of
# duplicating the kafka-go dependency.
FROM golang:1.25.8-bookworm AS build

WORKDIR /opt/banjax
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /usr/local/bin/kafka-cmd-tester ./supporting-containers/kafka-cmd-tester

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/kafka-cmd-tester /usr/local/bin/kafka-cmd-tester

ENTRYPOINT ["/usr/local/bin/kafka-cmd-tester"]
