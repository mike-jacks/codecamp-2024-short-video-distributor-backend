FROM golang:1.23.1-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o short-video-distributor .

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/short-video-distributor .

EXPOSE 8080

CMD ["./short-video-distributor"]


