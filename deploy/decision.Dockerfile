FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
WORKDIR /app/decision-service
RUN go mod download
RUN CGO_ENABLED=0 go build -o /out/fastgate ./cmd/fastgate

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /out/fastgate /usr/local/bin/fastgate
COPY decision-service/config.example.yaml /app/config.yaml
EXPOSE 8080
ENV FASTGATE_CONFIG=/app/config.yaml
ENTRYPOINT ["/usr/local/bin/fastgate"]
