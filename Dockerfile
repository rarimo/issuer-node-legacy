FROM golang:1.19 as buildbase

ARG VERSION
WORKDIR /go/src/gitlab.com/rarimo/issuer-node
COPY . .

RUN GOBIN=/usr/local/bin CGO_ENABLED=1 GOOS=linux go install -buildvcs=false -ldflags "-X main.build=${VERSION}" /go/src/gitlab.com/rarimo/issuer-node/cmd...

FROM alpine:3.18.2

RUN apk --update add --no-cache musl libstdc++ gcompat libgomp ca-certificates

WORKDIR /

COPY --from=buildbase "/go/src/gitlab.com/rarimo/issuer-node/api" "/api"
COPY --from=buildbase "/go/src/gitlab.com/rarimo/issuer-node/api_ui" "/api_ui"
COPY --from=buildbase "/go/pkg/mod/github.com/iden3/wasmer-go@v0.0.1" "/go/pkg/mod/github.com/iden3/wasmer-go@v0.0.1"
COPY --from=buildbase "/go/src/gitlab.com/rarimo/issuer-node/pkg" "/etc"
COPY --from=buildbase "/usr/local/bin" "/usr/local/bin"
