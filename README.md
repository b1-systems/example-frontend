# example-frontend

## Installation

```bash
git clone https://tk-sls.de/gitlab/golang-oidc/example-frontend.git
cd example-frontend
go mod tidy
go build
sudo mkdir /usr/local/example-frontend
sudo cp example-frontend /usr/local/example-frontend
sudo cp example-frontend.service /etc/systemd/system
sudo systemctl daemon-reload
```

## Configuration

```bash
sudo cp example-frontend.ini.sample /usr/local/example-frontend/example-frontend.ini
sudo vi /usr/local/example-frontend/example-frontend.ini
```

Example `example-frontend.ini`:

```
[example-frontend]
# These values are provided by your IdP for your confidential client
clientID = example-frontend
clientSecret = secret_as_set_in_idp

# This URL will be used for endpoint discovery of your IdP
providerUrl = https://your_idp_url/realms/golang-oidc

# The "example-frontend" server serves an URI "/auth/oidc/callback":
redirectCallbackUrl = https://your_frontend_url/auth/oidc/callback

# This should be the URL of the URI "/" of your "example-frontend" server:
redirectLoginUrl = https://your_frontend_url/example-frontend/

# See https://tk-sls.de/gitlab/golang-oidc/example-frontend
backendServiceUrl = https://tk-sls.de/example-backend/

# See https://tk-sls.de/gitlab/golang-oidc/example-resource
resourceServiceUrl = https://tk-sls.de/example-resource/

# Plain HTTP service address of this "example-frontend" server:
listenAddress = 0.0.0.0:80
```

