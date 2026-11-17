# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/omnislash ./cmd/omnislash

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/omnislash /usr/local/bin/omnislash
COPY --from=build /src/config.example.json /etc/omnislash/config.json
USER nonroot:nonroot
EXPOSE 3128 9090
HEALTHCHECK --interval=20s --timeout=5s --start-period=120s --retries=3 \
    CMD ["/usr/local/bin/omnislash", "healthcheck", "-url", "http://127.0.0.1:9090/readyz"]
ENTRYPOINT ["/usr/local/bin/omnislash"]
CMD ["serve", "-config", "/etc/omnislash/config.json", "-listen", "0.0.0.0:3128", "-stats", "0.0.0.0:9090"]
