# example-frontend

## Overview

1. Demonstration of OAuth2 Authorization Code Grant  
   See also: <https://oauth.net/2/grant-types/authorization-code/>
2. Demonstration of "state" parameter to authentication code request and authorization response  
   See also: <https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes>
3. Demonstration of "nonce" parameter to authentication code request and ID token claim  
   See also: <https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes>
4. Demonstration of `code_challenge` parameter to authentication code request and
   `code_verifier` parameter to token exchange (Proof Key for Code Exchange, PKCE)  
   See also: <https://oauth.net/2/pkce/>  
   See also (code example): <https://github.com/zjutjh/User-Center/blob/main/test/test_client.go>
5. Demonstration of OpenID Connect Back-Channel Logout 1.0  
   See also: <https://openid.net/specs/openid-connect-backchannel-1_0.html>

## Installation

```bash
git clone https://github.com/b1-systems/example-frontend.git
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

# See https://github.com/b1-systems/example-frontend
backendServiceUrl = https://www.example.test/example-backend/

# See https://github.com/b1-systems/example-resource
resourceServiceUrl = https://www.example.test/example-resource/

# Plain HTTP service address of this "example-frontend" server:
listenAddress = 0.0.0.0:80
```

# Start

```bash
systemctl start example-frontend.service
journalctl -xefu  example-frontend.service
```

