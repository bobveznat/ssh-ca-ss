package ssh_ca

import (
    "encoding/json"
    "os"
)

type RequesterConfig struct {
    PublicKeyPath string
}

func LoadRequesterConfig(config_path string) (map[string]RequesterConfig, error) {
    environment_configs := make(map[string]RequesterConfig)

    file, err := os.Open(config_path)
    if err != nil {
        return nil, err
    }

    buf := make([]byte, 1<<16)
    count, err := file.Read(buf)
    if err != nil {
        return nil, err
    }

    err = json.Unmarshal(buf[0:count], &environment_configs)
    if err != nil {
        return nil, err
    }

    return environment_configs, nil

}
