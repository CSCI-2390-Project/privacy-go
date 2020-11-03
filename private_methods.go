package privacy

import (
	"github.com/fernet/fernet-go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"sync"
)

var once sync.Once
var encoded_key string

type cryptmode int

const (
	encryptMode cryptmode = iota
	decryptMode
	permissionedDecryptMode
)

type action int

const (
	copying action = iota
	modifying
	printing
)

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
func encrypt(stringToEncrypt string) (string, error) {
	// validate we aren't passing in an already encrypted string!
	if isFernetToken([]byte(stringToEncrypt)) {
		return stringToEncrypt, nil
	}

	tok, err := fernet.EncryptAndSign([]byte(stringToEncrypt), fernet.MustDecodeKeys(encoded_key)[0])
	if err != nil {
		return stringToEncrypt, err
	}
	return string(tok), err
}

// can only support strings
func decrypt(encryptedString string) string {

	// validate we aren't passing in an already decrypted string!
	if !isFernetToken([]byte(encryptedString)) {
		return encryptedString
	}

	return string(fernet.VerifyAndDecrypt([]byte(encryptedString), 0, fernet.MustDecodeKeys(encoded_key)))
}

func isFernetToken(token []byte) bool {
	msg := fernet.VerifyAndDecrypt(token, 0, fernet.MustDecodeKeys(encoded_key))
	return msg != nil
}

// `recursiveCrypt` examines all the field values of a message, and encrypts / decrypts them
// based on the action.
func recursiveCrypt(raw_message proto.Message, mode cryptmode) {

	protomessage := raw_message.ProtoReflect()

	protomessage.Range(func(fd protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if fd.IsList() {
			listValue := value.List()
			for i := 0; i < listValue.Len(); i++ {
				message_element := listValue.Get(i)
				if fd.Kind() == protoreflect.MessageKind {
					recursiveCrypt(message_element.Message().Interface(), mode)
				}
				listValue.Set(i, message_element)
			}
		} else {
			switch fd.Kind() {
			case protoreflect.StringKind:

				switch mode {
				case encryptMode:

					new_value, err := encrypt(value.String())
					if err != nil {
						panic(err)
					}
					protomessage.Set(fd, protoreflect.ValueOf(new_value))

				case decryptMode:

					new_value := decrypt(value.String())
					protomessage.Set(fd, protoreflect.ValueOf(new_value))

				case permissionedDecryptMode:

					new_value := value.String()
					if isActionAllowed(protomessage.Descriptor().Name(), fd.Name(), printing, getStackTrace()) {
						new_value = decrypt(value.String())
					}
					protomessage.Set(fd, protoreflect.ValueOf(new_value))

				default:
				}

			case protoreflect.MessageKind:
				message := value.Message()
				recursiveCrypt(message.Interface(), mode)
				protomessage.Set(fd, protoreflect.ValueOf(message))
			default:
			}
		}
		return true
	})

}
