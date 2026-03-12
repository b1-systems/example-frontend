/* author: B1 Systems GmbH
 * authoremail: info@b1-systems.de
 * license: MIT License <https://opensource.org/licenses/MIT>
 * summary: OpenID Connect example
 * */

package secret

import (
  "fmt"
  "log"
  "os"
  "path/filepath"
)

func ReadSecret(secretName string) (string, error) {
  secretPath := filepath.Join("/run/secrets", secretName)
  content, err := os.ReadFile(secretPath)

  if err == nil {
    log.Printf("Read secret %s from path %s: %s", secretName, secretPath, content)
  } else {
    return "", fmt.Errorf("failed to read secret file %s: %v", secretPath, err)
  }

  return string(content), nil
}

/* vim: set tabstop=2 shiftwidth=2 softtabstop=2 expandtab: */
