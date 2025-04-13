package usecase

import (
	"context"
	"fmt"
	"log"
	"time"

	"auth-user-api/internal/model"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

type TokenUseCase struct {
	JwtConfig   *model.JWTConfig
	RedisClient *redis.Client
	Log         *logrus.Logger
}

func NewTokenUseCase(jwtConfig *model.JWTConfig, redisClient *redis.Client, log *logrus.Logger) *TokenUseCase {
	return &TokenUseCase{
		JwtConfig:   jwtConfig,
		RedisClient: redisClient,
		Log:         log,
	}
}

func (c *TokenUseCase) GenerateToken(id string, role string) (string, string, string, time.Time, error) {

	tokenID := uuid.New().String()
	claims := &model.UserClaims{
		ID:      id,
		Role:    role,
		TokenID: tokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(c.JwtConfig.AccessExpiry)),
			Issuer:    c.JwtConfig.Issuer,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessTokenString, err := accessToken.SignedString([]byte(c.JwtConfig.SecretKey))
	if err != nil {
		c.Log.Warnf("Failed to generate access token : %+v", err)
		return "", "", "", time.Time{}, err
	}

	expiresAccessToken := claims.ExpiresAt.Time

	refreshClaims := &model.UserClaims{
		ID:      id,
		Role:    role,
		TokenID: tokenID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(c.JwtConfig.RefreshExpiry)),
			Issuer:    c.JwtConfig.Issuer,
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(c.JwtConfig.SecretKey))
	if err != nil {
		c.Log.Warnf("Failed to generate refresh token : %+v", err)
		return "", "", "", time.Time{}, err
	}

	return accessTokenString, refreshTokenString, tokenID, expiresAccessToken, nil
}

func (c *TokenUseCase) ValidateToken(tokenString string) (*model.Auth, error) {
	var auth *model.Auth

	log.Println("tokenString: ", tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &model.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}

		return []byte(c.JwtConfig.SecretKey), nil
	})
	if err != nil {
		c.Log.Warnf("Failed to validate token : %+v", err)
		return nil, err
	}

	claims, ok := token.Claims.(*model.UserClaims)
	if !ok || !token.Valid {
		c.Log.Warnf("Failed to validate token : %+v", jwt.ErrInvalidKey)
		return nil, jwt.ErrInvalidKey
	}

	auth = &model.Auth{
		ID:   claims.ID,
		Role: claims.Role,
	}

	return auth, nil
}

func (c *TokenUseCase) GetToken(id string) (string, error) {
	ctx := context.Background()
	token, err := c.RedisClient.Get(ctx, id).Result()
	if err != nil {
		c.Log.Warnf("Failed to get token : %+v", err)
		return "", err
	}

	return token, nil
}

func (c *TokenUseCase) GetTTLOfToken(id string) time.Duration {
	ctx := context.Background()
	ttl := c.RedisClient.TTL(ctx, id).Val()
	if ttl == 0 {
		c.Log.Warnf("Failed to get token ttl")
		return 0
	}

	return ttl
}

func (c *TokenUseCase) StoreToken(refreshToken string, refreshTokenID, userID string) error {
	ctx := context.Background()

	// store token to redis with expiry time
	err := c.RedisClient.Set(ctx, refreshTokenID, refreshToken, c.JwtConfig.RefreshExpiry).Err()
	if err != nil {
		c.Log.Warnf("Failed to store token: %+v", err)
		return err
	}

	// save token to user token set
	userTokenSetKey := fmt.Sprintf("user:%s:tokens", userID)
	err = c.RedisClient.SAdd(ctx, userTokenSetKey, refreshTokenID).Err()
	if err != nil {
		c.Log.Warnf("Failed to add token to user set: %+v", err)
		return err
	}

	// set expiry for user token set
	_ = c.RedisClient.Expire(ctx, userTokenSetKey, c.JwtConfig.RefreshExpiry).Err()

	return nil
}

func (c *TokenUseCase) DeleteToken(token string) error {
	ctx := context.Background()
	err := c.RedisClient.Del(ctx, token).Err()
	if err != nil {
		c.Log.Warnf("Failed to delete token : %+v", err)
		return err
	}

	return nil
}

func (c *TokenUseCase) DeleteAllTokenMember(userID string) error {
	// Hapus semua token yang terkait dengan userID
	ctx := context.Background()
	key := fmt.Sprintf("user:%s:tokens", userID)

	// Ambil semua token ID
	tokenIDs, err := c.RedisClient.SMembers(ctx, key).Result()
	if err != nil {
		return err
	}

	// Hapus semua token dan tandai sebagai used
	for _, tokenID := range tokenIDs {
		_ = c.RedisClient.Del(ctx, tokenID).Err()
		_ = c.MarkTokenAsUsed(tokenID) // opsional
	}

	// Hapus juga set-nya
	return c.RedisClient.Del(ctx, key).Err()
}

func (c *TokenUseCase) IsTokenUsed(tokenID string) (bool, error) {
	ctx := context.Background()
	key := tokenID + ":used"

	exists, err := c.RedisClient.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}

func (c *TokenUseCase) MarkTokenAsUsed(tokenID string) error {
	ctx := context.Background()
	key := tokenID + ":used"
	// Simpan key ke Redis dengan nilai true dan waktu kedaluwarsa 5 menit
	return c.RedisClient.Set(ctx, key, true, 5*time.Minute).Err()
}
