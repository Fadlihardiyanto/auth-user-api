package util

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	_ "github.com/spf13/viper/remote"
	"github.com/ua-parser/uap-go/uaparser"
	"gorm.io/datatypes"
)

func BindFromJson(dest any, filename, path string) error {
	v := viper.New()

	v.SetConfigType("json")
	v.AddConfigPath(path)
	v.SetConfigName(filename)

	err := v.ReadInConfig()
	if err != nil {
		return err
	}

	err = v.Unmarshal(&dest)
	if err != nil {
		logrus.Errorf("failed to unmarshal configuration: %v", err)
		return err
	}

	return nil
}

func SetEnvFromConsulKV(v *viper.Viper) error {
	env := make(map[string]any)

	err := v.Unmarshal(&env)
	if err != nil {
		logrus.Errorf("failed to unmarshal configuration: %v", err)
		return err
	}

	for k, v := range env {
		var (
			valOf = reflect.ValueOf(v)
			val   string
		)

		switch valOf.Kind() {
		case reflect.String:
			val = valOf.String()
		case reflect.Int:
			val = strconv.Itoa(int(valOf.Int()))
		case reflect.Uint:
			val = strconv.Itoa(int(valOf.Uint()))
		case reflect.Float32:
			val = strconv.Itoa(int(valOf.Float()))
		case reflect.Float64:
			val = strconv.Itoa(int(valOf.Float()))
		case reflect.Bool:
			val = strconv.FormatBool(valOf.Bool())
		}

		err := os.Setenv(k, val)
		if err != nil {
			logrus.Errorf("failed to set environment variable: %v", err)
			return err
		}
	}

	return nil
}

func BindFromConsul(dest any, endPoint, path string) error {
	v := viper.New()

	v.SetConfigType("json")

	err := v.AddRemoteProvider("consul", endPoint, path)
	if err != nil {
		logrus.Errorf("failed to add remote provider: %v", err)
		return err
	}

	err = v.ReadRemoteConfig()
	if err != nil {
		logrus.Errorf("failed to read remote configuration: %v", err)
		return err
	}

	err = v.Unmarshal(&dest)
	if err != nil {
		logrus.Errorf("failed to unmarshal configuration: %v", err)
		return err
	}

	err = SetEnvFromConsulKV(v)
	if err != nil {
		logrus.Errorf("failed to set environment variable: %v", err)
		return err
	}

	return nil

}

// Generate secure random token
func GenerateToken(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func MapToJSON(m map[string]string) string {
	jsonData, err := json.Marshal(m)
	if err != nil {
		return `{"error": "failed to process error message"}`
	}
	return string(jsonData)
}

func ConvertStringToTime(dateStr, format string) (time.Time, error) {
	t, err := time.Parse(format, dateStr)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

func GetDeviceAndIP(ctx *fiber.Ctx) (string, datatypes.JSON, error) {
	ip := ctx.IP()
	if ip == "" {
		logrus.Warnf("failed to get IP address")
		return "", nil, fiber.ErrBadRequest
	}
	device := ctx.Get("User-Agent")
	if device == "" {
		logrus.Warnf("failed to get User-Agent")
		return "", nil, fiber.ErrBadRequest
	}

	parser := uaparser.NewFromSaved()
	ua := parser.Parse(device)

	deviceInfo := map[string]string{
		"user_agent": ctx.Get("User-Agent"),
		"os":         strings.TrimSpace(fmt.Sprintf("%s %s", ua.Os.Family, ua.Os.Major)),
		"browser":    ua.UserAgent.Family + " " + ua.UserAgent.Major,
		"device":     ua.Device.Family,
	}

	deviceJson, _ := json.Marshal(deviceInfo)

	return ip, deviceJson, nil
}
