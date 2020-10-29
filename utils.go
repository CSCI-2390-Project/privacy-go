package privacy

import (
    "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/reflect/protoreflect"
)

type Mode int

const (
    encryptMode Mode = iota
    decryptMode
    permissionedEncryptMode
    permissionedDecryptMode
)

// `recursiveCrypt` examines all the field values of a message, and encrypts / decrypts them.
func recursiveCrypt(raw_message proto.Message, mode Mode) {

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
                    new_value := PermissionedDecrypt(value.String())
                    protomessage.Set(fd, protoreflect.ValueOf(new_value))
                case permissionedEncryptMode:
                    new_value, err := PermissionedEncrypt(value.String())
                    if err != nil {
                        panic(err)
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

// `recursiveCrypt` examines all the field values of a message, and encrypts / decrypts each field
// if a policy passes for that module.
func PermissionedRecursiveCrypt(raw_message proto.Message) {
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

// Meant for cases where you might want to get a value
func PermissionedDecrypt(text string) string {
    // todo: use policies here!
    return decrypt(text)
}

// Meant for cases where you might want to set a value
func PermissionedEncrypt(text string) (string, error) {
    // todo: use policies here!
    encrypted, err := encrypt(text)
    if err != nil {
        panic(err)
    }
    return encrypted, err
}
