/* 1. Demonstration of the OAuth2 Authorization Code Grant
      See also: https://oauth.net/2/grant-types/authorization-code/
   2. Demonstration of "state" parameter to authentication code request and authorization response
      See also: https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
   3. Demonstration of "nonce" parameter to authentication code request and ID token claim
      See also: https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
   4. Demonstration of "code_challenge" parameter to authentication code request,
      "code_verifier" parameter to token exchange (Proof Key for Code Exchange, PKCE)
      See also: https://oauth.net/2/pkce/
      See also (code example): https://github.com/zjutjh/User-Center/blob/main/test/test_client.go */

package main

import (
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "errors"
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

type ref struct {
  name string
  value *string
}

func (r ref) readValue(cs *ini.Section) error {
  *r.value = cs.Key(r.name).String()

  if *r.value == "" {
    return errors.New(fmt.Sprintf("No value for name %s", r.name))
  } else {
    return nil
  }
}

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

  arr := [...]ref{
    {"clientID", &clientID},
    {"clientSecret", &clientSecret},
    {"providerUrl", &providerUrl},
    {"redirectCallbackUrl", &redirectCallbackUrl},
    {"redirectLoginUrl", &redirectLoginUrl},
    {"backendServiceUrl", &backendServiceUrl},
    {"resourceServiceUrl", &resourceServiceUrl},
    {"listenAddress", &listenAddress}}

  for _, r := range arr {
    if err := r.readValue(cs) ; err != nil {
      log.Fatal(fmt.Sprintf("Could not read value of %s", r.name))
      os.Exit(1)
    } else {
      var value string

      if r.name == "clientSecret" {
        value = "*REDACTED*"
      } else {
        value = *r.value
      }

      log.Printf("%s = %s\n", r.name, value);
    }
  }
}

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

func PkceChallenge(verifier string) string {
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

      codeChallenge := PkceChallenge(codeVerifier)

      s.Set("state", state)
      s.Set("nonce", nonce)
      s.Set("codeVerifier", codeVerifier)

      url := config.AuthCodeURL(
        state,
        oidc.Nonce(nonce),
        oauth2.SetAuthURLParam("code_challenge_method", "S256"),
        oauth2.SetAuthURLParam("code_challenge", codeChallenge))

      http.Redirect(w, r, url, http.StatusFound)
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
    Scopes: []string{oidc.ScopeOpenID, "profile", "email", "roles"},
  }

  sess := sessions.New(sessions.Config{
    Cookie: clientID,
    Expires: time.Hour * 2,
  })

  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    s := sess.Start(w, r);

    if auth, _ := s.GetBoolean("authenticated"); !auth {
      redirectToLogin(config, s, w, r);
    } else {
      access_token := s.GetString("access_token")

      id_token := s.GetString("id_token")
      idToken, err := verifier.Verify(ctx, id_token)

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
              "Parsed claims: exp = %s, aud = %s, email = %s, email_verified = %t\r\n\r\n",
              clientID,
              time.Unix(claims.Expires, 0).UTC(),
              claims.Audience,
              claims.Email,
              claims.Verified)))

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
    s := sess.Start(w, r);

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

    idToken, err := verifier.Verify(ctx, rawIDToken)

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

  log.Printf("Listening on http://%s/", listenAddress)
  log.Fatal(http.ListenAndServe(listenAddress, nil))
}
