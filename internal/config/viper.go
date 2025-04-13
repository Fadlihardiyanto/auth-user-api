package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

func NewViper() *viper.Viper {
	v := viper.New()

	// Use .env format
	v.SetConfigFile(".env")

	// Allow reading from ENV directly too
	v.AutomaticEnv()

	// Replace dots with underscores so nested keys work from ENV
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	err := v.ReadInConfig()
	if err != nil {
		fmt.Printf("No .env file loaded (maybe you prefer inline ENV) — %v\n", err)
	}

	return v
}
