# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM golang:1.22.6-bookworm

RUN set -x \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
		iptables ipset

RUN mkdir -p /opt/banjax
COPY ./ /opt/banjax/
RUN cd /opt/banjax && go test && go build

RUN mkdir -p /etc/banjax
COPY ./banjax-config.yaml /etc/banjax/
# COPY ./caroot.pem /etc/banjax/
# COPY ./certificate.pem /etc/banjax/
# COPY ./key.pem /etc/banjax/
# COPY ./internal/sha-inverse-challenge.html /etc/banjax/
# COPY ./internal/password-protected-path.html /etc/banjax/

RUN mkdir -p /var/log/banjax

EXPOSE 8081

WORKDIR /opt/banjax

# To enable live reload for dev, uncomment the following lines
# COPY ./.air.toml /opt/banjax/
# RUN go install github.com/air-verse/air@latest
# RUN mkdir -p /opt/banjax/tmp
# CMD ["air", "-c", ".air.toml"]
CMD ["./banjax"]
