FROM --platform=$BUILDPLATFORM golang:1.23.5-bookworm AS builder-basis
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app/netapply

COPY go.mod go.mod
COPY go.sum go.sum


RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go mod download


FROM --platform=$BUILDPLATFORM golang:1.23.5-bookworm AS builder
ARG TARGETOS
ARG TARGETARCH

COPY --from=builder-basis /go/pkg /go/pkg

WORKDIR /app/netapply

COPY . .

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o bin/netapply ./cmd/netapply

ENTRYPOINT ["/app/netapply/bin/netapply"]

FROM debian:bookworm

COPY --from=builder /app/netapply/bin/netapply /usr/local/bin/netapply

ENTRYPOINT ["/usr/local/bin/netapply"]
