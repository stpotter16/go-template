package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
    argonIterations uint32 = 2
    argonMemory uint32 = 19 * 1024
    argonThreads uint8 = 1
    argonSaltLength uint32 = 16
    argonKeyLength uint32 = 32
)

func HashPassword(password string) (string, error) {
    salt, err := generateSalt(argonSaltLength)
    if err != nil {
        return "", err
    }
    hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonThreads, argonKeyLength)

    base64Salt := base64.RawStdEncoding.EncodeToString(salt)
    base64Hash := base64.RawStdEncoding.EncodeToString(hash)

    encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonIterations, argonThreads, base64Salt, base64Hash)
    return encodedHash, nil
}

func VerifyPassword(password string, encodedHash string) (bool, error) {
    salt, hash, err := decodeHash(encodedHash)
    if err != nil {
        return false, err
    }

    otherHash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonThreads, argonKeyLength)

    if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
        return true, nil
    }

    return false, nil
}

func generateSalt(saltLength uint32) ([]byte, error) {
    b := make([]byte, saltLength)
    _, err := rand.Read(b)
    if err != nil {
        return nil, err
    }
    return b, nil
}

func decodeHash(passwordHash string) ([]byte, []byte, error) {
    strVals := strings.Split(passwordHash, "$")
    if len(strVals) != 6 {
        return nil, nil, errors.New("Invalid password hash")
    }

    salt, err := base64.RawStdEncoding.DecodeString(strVals[4])
    if err != nil {
        return nil, nil, err
    }

    hash, err := base64.RawStdEncoding.DecodeString(strVals[5])
    if err != nil {
        return nil, nil, err
    }

    return salt, hash, nil
}

