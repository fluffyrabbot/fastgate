FROM golang:1.24.7-alpine AS builder
WORKDIR /app/decision-service
COPY decision-service/go.mod decision-service/go.sum ./
RUN go mod download
COPY decision-service/cmd ./cmd
COPY decision-service/internal ./internal
RUN CGO_ENABLED=0 go build -o /out/fastgate ./cmd/fastgate

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /out/fastgate /usr/local/bin/fastgate
COPY decision-service/config.example.yaml /app/config.yaml
COPY challenge-page /app/challenge-page
EXPOSE 8080
ENV FASTGATE_CONFIG=/app/config.yaml
ENV CHALLENGE_PAGE_DIR=/app/challenge-page
ENTRYPOINT ["/usr/local/bin/fastgate"]
