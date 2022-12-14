/* author: B1 Systems GmbH
 * authoremail: info@b1-systems.de
 * license: MIT License <https://opensource.org/licenses/MIT>
 * summary: OpenID Connect example
 * */

/* 1. Demonstration of OAuth2 Authorization Code Grant
      See also: https://oauth.net/2/grant-types/authorization-code/
   2. Demonstration of "state" parameter to authentication code request and authorization response
      See also: https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
   3. Demonstration of "nonce" parameter to authentication code request and ID token claim
      See also: https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
   4. Demonstration of "code_challenge" parameter to authentication code request and
      "code_verifier" parameter to token exchange (Proof Key for Code Exchange, PKCE)
      See also: https://oauth.net/2/pkce/
      See also (code example): https://github.com/zjutjh/User-Center/blob/main/test/test_client.go
   5. Demonstration of OpenID Connect Back-Channel Logout 1.0
      See also: https://openid.net/specs/openid-connect-backchannel-1_0.html */

package main

import (
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "fmt"
  "io"
  "io/ioutil"
  "log"
  "net/http"
  "os"
  "time"
  "github.com/coreos/go-oidc/v3/oidc"
  "github.com/kataras/go-sessions/v3"
  "golang.org/x/net/context"
  "golang.org/x/oauth2"
  "example-frontend/ini"
)

var (
  clientName = "example-frontend"
  clientID = ""
  clientSecret = ""
  providerUrl = ""
  redirectCallbackUrl = ""
  redirectLoginUrl = ""
  backendServiceUrl = ""
  resourceServiceUrl = ""
  listenAddress = ""
)

func randString(nByte int) (string, error) {
  b := make([]byte, nByte)

  if _, err := io.ReadFull(rand.Reader, b); err != nil {
    return "", err
  }

  return base64.RawURLEncoding.EncodeToString(b), nil
}

func GenerateCodeVerifier(length int) (string, error) {
  if length > 128 {
    length = 128
  } else if length < 43 {
    length = 43
  }

  result, err := randString(length)

  if err != nil {
    log.Printf("Could not generate random string of length %d for PKCE code verifier")
    return result, err
  }

  return result, nil
}

func ComputePkceChallenge(verifier string) string {
  sum := sha256.Sum256([]byte(verifier))
  challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sum[:])

  return (challenge)
}

func redirectToLogin(config oauth2.Config, s *sessions.Session, w http.ResponseWriter, r *http.Request) {
  state, err := randString(16)

  if err != nil {
    log.Fatal(err)
    http.Error(w, "Internal error", http.StatusInternalServerError)
  } else {
    nonce, err := randString(16)

    if err != nil {
      log.Fatal(err)
      http.Error(w, "Internal error", http.StatusInternalServerError)
    } else {
      codeVerifier, err := GenerateCodeVerifier(43)

      if err != nil {
        log.Fatal(err)
        http.Error(w, "Internal error", http.StatusInternalServerError)
        return
      }

      codeChallenge := ComputePkceChallenge(codeVerifier)

      s.Set("state", state)
      s.Set("nonce", nonce)
      s.Set("codeVerifier", codeVerifier)

      url := config.AuthCodeURL(
        state,
        oidc.Nonce(nonce),
        oauth2.SetAuthURLParam("code_challenge_method", "S256"),
        oauth2.SetAuthURLParam("code_challenge", codeChallenge))
        oauth2.SetAuthURLParam("claims", "{\"id_token\":{\"acr\":{\"essential\": true,\"values\": [\"gold\"]}}}")
        oauth2.SetAuthURLParam("test", "xyz")

      http.Redirect(w, r, url, http.StatusFound)
    }
  }
}

func main() {
  arr := []ini.Ref{
    {"clientID", &clientID},
    {"clientSecret", &clientSecret},
    {"providerUrl", &providerUrl},
    {"redirectCallbackUrl", &redirectCallbackUrl},
    {"redirectLoginUrl", &redirectLoginUrl},
    {"backendServiceUrl", &backendServiceUrl},
    {"resourceServiceUrl", &resourceServiceUrl},
    {"listenAddress", &listenAddress}}

  ini.ReadIni(clientName, arr)

  ctx := context.Background()
  provider, err := oidc.NewProvider(ctx, providerUrl)

  if err != nil {
    log.Fatal(err)
    os.Exit(1)
  }

  idTokenVerifyerConfig := &oidc.Config{
    ClientID: clientID,
  }

  idTokenVerifier := provider.Verifier(idTokenVerifyerConfig)

  logoutTokenVerifyerConfig := &oidc.Config{
    ClientID: clientID,
    SkipExpiryCheck: true,
  }

  logoutTokenVerifier := provider.Verifier(logoutTokenVerifyerConfig)

  oidc_sid_to_session := make(map[string]string)

  config := oauth2.Config{
    ClientID: clientID,
    ClientSecret: clientSecret,
    Endpoint: provider.Endpoint(),
    RedirectURL: redirectCallbackUrl,
    Scopes: []string{oidc.ScopeOpenID, "profile", "email", "roles"},
  }

  sess := sessions.New(sessions.Config{
    Cookie: clientID,
    Expires: time.Hour * 2,
  })

  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    s := sess.Start(w, r)

    if auth, _ := s.GetBoolean("authenticated"); !auth {
      redirectToLogin(config, s, w, r);
    } else {
      access_token := s.GetString("access_token")

      id_token := s.GetString("id_token")
      idToken, err := idTokenVerifier.Verify(ctx, id_token)

      if err != nil {
        s.Set("authenticated", false)
        log.Printf("Unable to verify ID token: %s; redirecting user agent to login", err)
        redirectToLogin(config, s, w, r);
      } else {
        err = idToken.VerifyAccessToken(access_token)

        if err != nil {
          s.Set("authenticated", false)
          log.Printf("Unable to verify access token: %s; redirecting user agent to login", err)
          http.Error(w, "Bad request", http.StatusBadRequest)
        } else {
          var claims struct {
            Sid string `json:"sid"`
            Expires int64 `json:"exp"`
            Audience []string `json:"aud"`
            Email string `json:"email"`
            Verified bool `json:"email_verified"`
          }

          if err := idToken.Claims(&claims); err != nil {
            log.Printf("Unable to parse claims from ID token: %s", err)
            http.Error(w, "Bad request", http.StatusBadRequest)
          } else {
            w.Write([]byte(fmt.Sprintf("Client %s got access token: %s\r\n\r\n", clientID, access_token)))
            w.Write([]byte(fmt.Sprintf("Client %s got ID token: %s\r\n\r\n", clientID, id_token)))
            w.Write([]byte(fmt.Sprintf(
              "--------%s--------\r\n" +
              "Parsed claims (from ID token):\r\n" +
              " * sid = %s\r\n" +
              " * exp = %s\r\n" +
              " * aud = %s\r\n" +
              " * email = %s\r\n" +
              " * email_verified = %t\r\n\r\n",
              clientID,
              claims.Sid,
              time.Unix(claims.Expires, 0).UTC(),
              claims.Audience,
              claims.Email,
              claims.Verified)))

            // Remember OIDC session ID -> Kataras session ID
            oidc_sid_to_session[claims.Sid] = s.ID()

            req, err := http.NewRequest("GET", backendServiceUrl, nil)

            req.Header = http.Header{
              "Authorization": {"Bearer " + id_token},
            }

            client := http.Client{}

            res , err := client.Do(req)

	          if err != nil {
              log.Printf("Web request to %s failed: %s (status: %d)", backendServiceUrl, err, res.StatusCode)
              w.Write([]byte("Making web request to " + backendServiceUrl + " failed."))
	          } else {
              body, err := ioutil.ReadAll(res.Body)

	            if err != nil {
                log.Printf("Reading result of web request to %s failed: %s (status: %d)", backendServiceUrl, err, res.StatusCode)
                w.Write([]byte("Reading result of web request to " + backendServiceUrl + " failed."))
              } else {
                sb := string(body)
                w.Write([]byte("Result of web request to " + backendServiceUrl + ":\r\n" + sb + "\r\n"))
              }
            }

            req, err = http.NewRequest("GET", resourceServiceUrl, nil)

            req.Header = http.Header{
              "Authorization": {"Bearer " + access_token},
            }

            res , err = client.Do(req)

	          if err != nil {
              log.Printf("Web request to %s failed: %s (status: %d)", resourceServiceUrl, err, res.StatusCode)
              w.Write([]byte("Making web request to " + resourceServiceUrl + " failed."))
	          } else {
              body, err := ioutil.ReadAll(res.Body)

	            if err != nil {
                log.Printf("Reading result of web request to %s failed: %s (status: %d)", resourceServiceUrl, err, res.StatusCode)
                w.Write([]byte("Reading result of web request to " + resourceServiceUrl + " failed."))
              } else {
                sb := string(body)
                w.Write([]byte("Result of web request to " + resourceServiceUrl + ":\r\n" + sb))
              }
            }
          }
        }
      }
    }
  })

  http.HandleFunc("/auth/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
    s := sess.Start(w, r)

    state := s.GetString("state")

    if r.URL.Query().Get("state") != state {
      log.Printf("\"state\" did not match, possible clickjack attempt")
      http.Error(w, "Bad request", http.StatusBadRequest)
      return
    }

    codeVerifier := s.GetString("codeVerifier")

    if err != nil {
      log.Printf("\"codeVerifier\" not set, possible clickjack attempt")
      http.Error(w, "Bad request", http.StatusBadRequest)
      return
    }

    oauth2Token, err := config.Exchange(
      ctx,
      r.URL.Query().Get("code"),
      oauth2.SetAuthURLParam("code_verifier", codeVerifier))

    if err != nil {
      log.Printf("Failed to exchange token: %s", err.Error())
      http.Error(w, "Internal server error", http.StatusInternalServerError)
      return
    }

    rawIDToken, ok := oauth2Token.Extra("id_token").(string)

    if !ok {
      log.Printf("No id_token field in oauth2 token")
      http.Error(w, "Internal server error", http.StatusInternalServerError)
      return
    }

    idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)

    if err != nil {
      log.Printf("Failed to verify ID Token: %s", err.Error())
      http.Error(w, "Internal server error", http.StatusInternalServerError)
      return
    }

    nonce := s.GetString("nonce")

    if idToken.Nonce != nonce {
      log.Printf("\"nonce\" did not match, possible clickjack attempt")
      http.Error(w, "Bad request", http.StatusBadRequest)
      return
    }

    s.Set("authenticated", true)
    s.Set("access_token", oauth2Token.AccessToken);
    s.Set("id_token", rawIDToken);

    http.Redirect(w, r, redirectLoginUrl, http.StatusFound)
  })

  http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    logout_token := r.Form.Get("logout_token")

    log.Printf("The /logout handler was called; logout_token = %s", string(logout_token))

    if logoutToken, err := logoutTokenVerifier.Verify(ctx, logout_token) ; err != nil {
      log.Printf("logout_token could not be verified: %s", err)
      http.Error(w, "Bad request", http.StatusBadRequest)
    } else {
      var claims struct {
        Sid string `json:"sid"`
      }

      if err := logoutToken.Claims(&claims); err != nil {
        log.Printf("Unable to parse claims from ID token: %s", err)
        http.Error(w, "Bad request", http.StatusBadRequest)
      } else {
        log.Printf("Received backchannel logout request for sid = %s", claims.Sid)

        if session_id, ok := oidc_sid_to_session[claims.Sid] ; ok {
          sess.DestroyByID(session_id)
          log.Printf("Requested destruction of browser session %s (OIDC sid=%s)", session_id, claims.Sid)
        } else {
          log.Printf("No browser session found for sid = %s", claims.Sid)
        }
      }
    }
  })

  log.Printf("Listening on http://%s/", listenAddress)
  log.Fatal(http.ListenAndServe(listenAddress, nil))
}
