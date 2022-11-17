# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
# 
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM golang:1.17.0-buster

RUN go get -u github.com/gin-gonic/gin

RUN mkdir -p /opt/hello-world
RUN mkdir -p /opt/hello-world/static/
COPY ./hello-world.go /opt/hello-world/
COPY ./go.mod /opt/hello-world/
COPY ./go.sum /opt/hello-world/
COPY ./static/logo.png /opt/hello-world/static/

EXPOSE 8080

WORKDIR /opt/hello-world
CMD ["go", "run", "hello-world.go"]
