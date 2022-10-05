package main

import (
  "crypto/rand"
  "encoding/base64"
  "fmt"
  "io"
  "io/ioutil"
  "log"
  "net/http"
  "os"
  "path/filepath"
  "time"
  "github.com/coreos/go-oidc/v3/oidc"
  "github.com/kataras/go-sessions/v3"
  "golang.org/x/net/context"
  "golang.org/x/oauth2"
  "gopkg.in/ini.v1"
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

func readIni() {
  ex, err := os.Executable()

  if err != nil {
    panic(err)
  }

  cfg, err := ini.Load(filepath.Join(filepath.Dir(ex), clientName + ".ini"))

  if err != nil {
    panic(err)
  }

  cs := cfg.Section(clientName)

  clientID = cs.Key("clientID").String()

  if clientID == "" {
    log.Fatal(clientName + ".ini does not specify clientID")
    os.Exit(1)
  }

  clientSecret = cs.Key("clientSecret").String()

  if clientSecret == "" {
    log.Fatal(clientName + ".ini does not specify clientSecret")
    os.Exit(1)
  }

  providerUrl = cs.Key("providerUrl").String()

  if providerUrl == "" {
    log.Fatal(clientName + ".ini does not specify providerUrl")
    os.Exit(1)
  }

  redirectCallbackUrl = cs.Key("redirectCallbackUrl").String()

  if redirectCallbackUrl == "" {
    log.Fatal(clientName + ".ini does not specify redirectCallbackUrl")
    os.Exit(1)
  }

  redirectLoginUrl = cs.Key("redirectLoginUrl").String()

  if redirectLoginUrl == "" {
    log.Fatal(clientName + ".ini does not specify redirectLoginUrl")
    os.Exit(1)
  }

  backendServiceUrl = cs.Key("backendServiceUrl").String()

  if backendServiceUrl == "" {
    log.Fatal(clientName + ".ini does not specify backendServiceUrl")
    os.Exit(1)
  }

  resourceServiceUrl = cs.Key("resourceServiceUrl").String()

  if resourceServiceUrl == "" {
    log.Fatal(clientName + ".ini does not specify resourceServiceUrl")
    os.Exit(1)
  }

  listenAddress = cs.Key("listenAddress").String()

  if listenAddress == "" {
    log.Fatal(clientName + ".ini does not specify listenAddress")
    os.Exit(1)
  }

  log.Printf(
    "Read configuration:\n" +
    " clientID = %s\n" +
    " clientSecret = %s\n" +
    " providerUrl = %s\n" +
    " redirectCallbackUrl = %s\n" +
    " redirectLoginUrl = %s\n" +
    " backendServiceUrl = %s\n" +
    " resourceServiceUrl = %s\n" +
    " listenAddress = %s\n",
    clientID,
    "*REDACTED*",
    providerUrl,
    redirectCallbackUrl,
    redirectLoginUrl,
    backendServiceUrl,
    resourceServiceUrl,
    listenAddress,
  )
}

func randString(nByte int) (string, error) {
  b := make([]byte, nByte)

  if _, err := io.ReadFull(rand.Reader, b); err != nil {
    return "", err
  }

  return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCookie(w http.ResponseWriter, r *http.Request, name, value string) {
  c := &http.Cookie{
    Name: name,
    Value: value,
    MaxAge: int(time.Hour.Seconds()),
    Secure: r.TLS != nil,
    HttpOnly: true,
  }

  http.SetCookie(w, c)
}

func redirectToLogin(config oauth2.Config, w http.ResponseWriter, r *http.Request) {
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
      setCookie(w, r, "state", state)
      setCookie(w, r, "nonce", nonce)

      http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
    }
  }
}

func main() {
  readIni()

  ctx := context.Background()
  provider, err := oidc.NewProvider(ctx, providerUrl)

  if err != nil {
    log.Fatal(err)
    os.Exit(1)
  }

  oidcConfig := &oidc.Config{
    ClientID: clientID,
  }

  verifier := provider.Verifier(oidcConfig)

  config := oauth2.Config{
    ClientID: clientID,
    ClientSecret: clientSecret,
    Endpoint: provider.Endpoint(),
    RedirectURL: redirectCallbackUrl,
    Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
  }

  sess := sessions.New(sessions.Config{
    Cookie: clientID,
    Expires: time.Hour * 2,
  })

  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    s := sess.Start(w, r);

    if auth, _ := s.GetBoolean("authenticated"); !auth {
      redirectToLogin(config, w, r);
    } else {
      access_token := s.GetString("access_token")

      id_token := s.GetString("id_token")
      idToken, err := verifier.Verify(ctx, id_token)

      if err != nil {
        s.Set("authenticated", false)
        log.Printf("Unable to verify ID token: %s; redirecting user agent to login", err)
        redirectToLogin(config, w, r);
      } else {
        err = idToken.VerifyAccessToken(access_token)

        if err != nil {
          s.Set("authenticated", false)
          log.Printf("Unable to verify access token: %s; redirecting user agent to login", err)
          http.Error(w, "Bad request", http.StatusBadRequest)
        } else {
          var claims struct {
            Expires int64 `json:"exp"`
            Audience []string `json:"aud"`
            Email string `json:"email"`
            Verified bool `json:"email_verified"`
          }

          if err := idToken.Claims(&claims); err != nil {
            log.Printf("Unable to parse claims from ID token: %s", err)
            http.Error(w, "Bad request", http.StatusBadRequest)
          } else {
            w.Write([]byte(fmt.Sprintf(
              "Client %s parsed claims: exp = %s, aud = %s, email = %s, email_verified = %t\r\n",
              clientID,
              time.Unix(claims.Expires, 0).UTC(),
              claims.Audience,
              claims.Email,
              claims.Verified)))

            w.Write([]byte("Making web request to " + backendServiceUrl + "\r\n"))

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

            w.Write([]byte("Making web request to " + resourceServiceUrl + "\r\n"))

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
    state, err := r.Cookie("state")

    if err != nil {
      log.Printf("Cookie \"state\" not set, possible clickjack attempt")
      http.Error(w, "Bad request", http.StatusBadRequest)
      return
    }

    if r.URL.Query().Get("state") != state.Value {
      log.Printf("Cookie \"state\" did not match, possible clickjack attempt")
      http.Error(w, "Bad request", http.StatusBadRequest)
      return
    }

    oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))

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

    idToken, err := verifier.Verify(ctx, rawIDToken)

    if err != nil {
      log.Printf("Failed to verify ID Token: %s", err.Error())
      http.Error(w, "Internal server error", http.StatusInternalServerError)
      return
    }

    nonce, err := r.Cookie("nonce")

    if err != nil {
      log.Printf("Cookie \"nonce\" not set, possible clickjack attempt")
      http.Error(w, "Bad request", http.StatusBadRequest)
      return
    }

    if idToken.Nonce != nonce.Value {
      log.Printf("Cookie \"nonce\" did not match, possible clickjack attempt")
      http.Error(w, "Bad request", http.StatusBadRequest)
      return
    }

    s := sess.Start(w, r);

    s.Set("authenticated", true)
    s.Set("access_token", oauth2Token.AccessToken);
    s.Set("id_token", rawIDToken);

    http.Redirect(w, r, redirectLoginUrl, http.StatusFound)
  })

  log.Printf("Listening on http://%s/", listenAddress)
  log.Fatal(http.ListenAndServe(listenAddress, nil))
}
