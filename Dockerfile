FROM golang as builder
RUN mkdir  /build
WORKDIR /build
COPY *go /build
RUN CGO_ENABLED=0 go build -o tlsecho *.go
FROM alpine
RUN mkdir /app
WORKDIR /app
COPY --from=builder /build/tlsecho /app
CMD ["./tlsecho"]