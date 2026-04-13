FROM golang:1.25 as builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o s3sentinel ./cmd/s3sentinel

FROM gcr.io/distroless/base-debian11

WORKDIR /app

COPY --from=builder /app/s3sentinel /app/s3sentinel

EXPOSE 8080 9090

ENTRYPOINT ["/app/s3sentinel"]
