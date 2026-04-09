FROM golang:1.26.1-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN go mod tidy
RUN go mod download
RUN go build -v -o XMBox -tags "sing xray hysteria2 with_quic with_grpc with_utls with_gvisor" -trimpath -ldflags "-s -w -buildid=" ./main

FROM alpine
RUN apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/XMBox/
COPY --from=builder /app/XMBox /usr/local/bin
COPY build_assets/ /usr/local/bin
ENTRYPOINT [ "XMBox", "--config", "/etc/XMBox/config.yaml"]