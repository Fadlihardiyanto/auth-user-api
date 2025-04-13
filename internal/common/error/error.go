package common

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

func HandleErrorResponse(ctx *fiber.Ctx, err error) error {
	if fe, ok := err.(*fiber.Error); ok {
		var errorMap map[string]string
		if json.Unmarshal([]byte(fe.Message), &errorMap) == nil {
			return ctx.Status(fe.Code).JSON(fiber.Map{"errors": errorMap})
		}
		return ctx.Status(fe.Code).JSON(fiber.Map{"errors": fiber.Map{"message": fe.Message}})
	}

	return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"errors": fiber.Map{"message": "Internal Server Error"},
	})
}

// getJSONFieldName mencari nama JSON berdasarkan field struct
func getJSONFieldName(structType reflect.Type, fieldName string) string {
	if field, found := structType.FieldByName(fieldName); found {
		jsonTag := field.Tag.Get("json")
		if jsonTag != "" {
			return strings.Split(jsonTag, ",")[0] // Ambil hanya nama JSON
		}
	}
	return fieldName // Jika tidak ada tag JSON, pakai nama struct
}

func FormatValidationError(err error, modelType reflect.Type) map[string]string {
	validationErrors := make(map[string]string)

	for _, err := range err.(validator.ValidationErrors) {
		fieldJSON := getJSONFieldName(modelType, err.StructField()) // Nama field JSON
		paramFieldJSON := getJSONFieldName(modelType, err.Param())  // Nama field JSON dari eqfield
		tag := err.Tag()

		var message string
		switch tag {
		case "required":
			message = fmt.Sprintf("%s harus diisi", fieldJSON)
		case "min":
			message = fmt.Sprintf("%s minimal harus %s karakter", fieldJSON, err.Param())
		case "max":
			message = fmt.Sprintf("%s maksimal %s karakter", fieldJSON, err.Param())
		case "email":
			message = fmt.Sprintf("%s harus berupa email yang valid", fieldJSON)
		case "eqfield":
			message = fmt.Sprintf("%s harus sama dengan %s", fieldJSON, paramFieldJSON)
		case "containsany":
			if err.Param() == "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
				message = fmt.Sprintf("%s harus mengandung setidaknya satu huruf besar", fieldJSON)
			} else if err.Param() == "abcdefghijklmnopqrstuvwxyz" {
				message = fmt.Sprintf("%s harus mengandung setidaknya satu huruf kecil", fieldJSON)
			} else if err.Param() == "0123456789" {
				message = fmt.Sprintf("%s harus mengandung setidaknya satu angka", fieldJSON)
			} else {
				message = fmt.Sprintf("%s harus mengandung setidaknya satu dari %s", fieldJSON, err.Param())
			}
		case "gte":
			message = fmt.Sprintf("%s harus lebih besar atau sama dengan %s", fieldJSON, err.Param())
		case "lte":
			message = fmt.Sprintf("%s harus lebih kecil atau sama dengan %s", fieldJSON, err.Param())
		case "gt":
			message = fmt.Sprintf("%s harus lebih besar dari %s", fieldJSON, err.Param())
		case "lt":
			message = fmt.Sprintf("%s harus lebih kecil dari %s", fieldJSON, err.Param())
		case "uuid":
			message = fmt.Sprintf("%s harus berupa UUID yang valid", fieldJSON)
		default:
			message = fmt.Sprintf("%s tidak valid", fieldJSON)
		}

		validationErrors[fieldJSON] = message
	}

	return validationErrors
}
