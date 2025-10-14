FROM golang:1.23.5-bookworm AS builder

WORKDIR /app/netapply

COPY . .

RUN go build -o bin/netapply ./main.go

ENTRYPOINT ["/app/netapply/bin/netapply"]

FROM debian:bookworm

COPY --from=builder /app/netapply/bin/netapply /usr/local/bin/netapply

ENTRYPOINT ["/usr/local/bin/netapply"]
