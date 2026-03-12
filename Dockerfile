FROM golang:1.26 AS build-stage
WORKDIR /app
COPY example-frontend.go go.mod go.sum ./
COPY ini /usr/local/go/src/example-frontend/ini
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /example-frontend

FROM scratch AS release-stage
COPY --from=build-stage /example-frontend /example-frontend
COPY example-frontend.ini.sample /example-frontend.ini
ENTRYPOINT ["/example-frontend"]
ENV CLIENT_ID=example-frontend
ENV CLIENT_SECRET=
ENV PROVIDER_URL=
ENV REDIRECT_CALLBACK_URL=
ENV REDIRECT_LOGIN_URL=
ENV BACKEND_SERVICE_URL=
ENV RESOURCE_SERVICE_URL=
ENV LISTEN_ADDRESS=0.0.0.0:80
