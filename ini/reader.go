/* author: B1 Systems GmbH
 * authoremail: info@b1-systems.de
 * license: MIT License <https://opensource.org/licenses/MIT>
 * summary: OpenID Connect example
 * */

package ini

import (
  "errors"
  "fmt"
  "log"
  "os"
  "regexp"
  "strings"
  "path/filepath"
  "gopkg.in/ini.v1"
)

type Ref struct {
  Name string
  Value *string
}

func (r Ref) ReadValue(cs *ini.Section) error {
  *r.Value = cs.Key(r.Name).String()

  if *r.Value == "" {
    return errors.New(fmt.Sprintf("No value for name %s", r.Name))
  } else {
    return nil
  }
}

func CamelToUpper(camel string) string {
  re := regexp.MustCompile(`[A-Z]?[a-z0-9]+`)
  matches := re.FindAllStringSubmatch(camel, -1)
  upper := make([]string, len(matches))

  for i := range matches {
    upper[i] = strings.ToUpper(matches[i][0])
  }

  return strings.Join(upper, "_")
}

func CheckEnv(name string) (string, error) {
  for _, env := range os.Environ() {
    pair := strings.Split(env, "=")

    if pair[0] == name {
      return pair[1], nil
    }
  }

  return "", errors.New(fmt.Sprintf("no such enviornment variable: %s", name))
}

func ReadIni(clientName string, arr []Ref) error {
  ex, err := os.Executable()

  if err != nil {
    return err
  }

  cfg, err := ini.Load(filepath.Join(filepath.Dir(ex), clientName + ".ini"))

  if err != nil {
    return err
  }

  cs := cfg.Section(clientName)

  for _, r := range arr {
    envName := CamelToUpper(r.Name)

    if value, err := CheckEnv(envName) ; err == nil && value != "" {
      log.Printf("Environment variable %s is set, using value for %s", envName, r.Name)
      *r.Value = value
    } else if err := r.ReadValue(cs) ; err != nil {
      return errors.New(fmt.Sprintf("Could not read value of %s", r.Name))
    }
  }

  return nil
}
