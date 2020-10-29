package privacy

import (
    "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/reflect/protoreflect"
)

type Mode int

const (
    encryptMode Mode = iota
    decryptMode
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
                if mode == encryptMode {
                    new_value, err := encrypt(value.String())
                    if err != nil {
                        panic(err)
                    }
                    protomessage.Set(fd, protoreflect.ValueOf(new_value))
                } else {
                    new_value := decrypt(value.String())
                    protomessage.Set(fd, protoreflect.ValueOf(new_value))
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
func PermissionedEncrypt(text string) string {
    // todo: use policies here!
    return encrypt(text)
}
