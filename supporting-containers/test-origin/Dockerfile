# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM golang:1.22.6-bookworm

WORKDIR /opt/hello-world

RUN mkdir -p /opt/hello-world
RUN mkdir -p /opt/hello-world/assets

COPY ./hello-world.go /opt/hello-world/
COPY ./go.mod /opt/hello-world/
COPY ./go.sum /opt/hello-world/
COPY ./assets/deflect_100.png /opt/hello-world/assets

RUN go build -o hello-world hello-world.go

EXPOSE 8080

CMD ["./hello-world"]
