FROM public.ecr.aws/docker/library/golang:1.18-alpine AS builder

RUN apk add --upate --no-cache git

ENV CGO_ENABLED=0
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . ./

RUN go build -o ecrscanresults main.go

FROM public.ecr.aws/docker/library/alpine:3.15 AS production

RUN apk add --update --no-cache ca-certificates
COPY --from=builder /src/ecrscanresults /ecrscanresults

CMD ["/ecrscanresults"]
