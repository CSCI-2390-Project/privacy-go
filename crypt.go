package privacy

import (
    "github.com/fernet/fernet-go"
    "sync"
)

var once sync.Once
var encoded_key string

// generate an encoded key just once
func init() {
    once.Do(func() {
        new_key := fernet.Key{}
        err := new_key.Generate()
        if err != nil {
            panic(err)
        }
        encoded_key = new_key.Encode()
    })
}

// can only support strings.
func Encrypt(stringToEncrypt string) (string, error) {
    // validate we aren't passing in an already encrypted string!
    if IsFernetToken([]byte(stringToEncrypt)) {
        return stringToEncrypt, nil
    }

    tok, err := fernet.EncryptAndSign([]byte(stringToEncrypt), fernet.MustDecodeKeys(encoded_key)[0])
    if err != nil {
        return stringToEncrypt, err
    }
    return string(tok), err
}

// can only support strings
func Decrypt(encryptedString string) string {

    // validate we aren't passing in an already decrypted string!
    if !IsFernetToken([]byte(encryptedString)) {
        return encryptedString
    }

    return string(fernet.VerifyAndDecrypt([]byte(encryptedString), 0, fernet.MustDecodeKeys(encoded_key)))
}

func IsFernetToken(token []byte) bool {
    msg := fernet.VerifyAndDecrypt(token, 0, fernet.MustDecodeKeys(encoded_key))
    return msg != nil
}
