package privacy

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Meant for cases where you might want to get a value - assumes you want to
// copy the data if a policy passes for that message, field and action.
func PermissionedDecrypt(messageName protoreflect.Name, fieldName protoreflect.Name, text string) string {

	if isActionAllowed(messageName, fieldName, copying, getStackTrace()) {
		return decrypt(text)
	}

	return text
}

// Meant for cases where you might want to set a value
// if a policy passes for that message, field and action.
func PermissionedEncrypt(messageName protoreflect.Name, fieldName protoreflect.Name, text string) (string, error) {

	if !isActionAllowed(messageName, fieldName, modifying, getStackTrace()) {
		return text, nil
	}

	encrypted, err := encrypt(text)
	if err != nil {
		panic(err)
	}
	return encrypted, err
}

// `recursiveCrypt` examines all the field values of a message, and encrypts / decrypts each field
// if a policy passes for that message and field. Assumes the action is printing.
func PermissionedRecursiveDecrypt(raw_message proto.Message) {
	recursiveCrypt(raw_message, permissionedDecryptMode)
}

// Unmarshal parses the wire-format message in b and places the result in m.
func Unmarshal(b []byte, m proto.Message) error {
	err := proto.Unmarshal(b, m)
	if err == nil {
		recursiveCrypt(m, encryptMode)
	}
	return err
}

// Marshal returns the wire-format encoding of m.
func Marshal(m proto.Message) ([]byte, error) {
	recursiveCrypt(m, decryptMode)
	return proto.Marshal(m)
}
