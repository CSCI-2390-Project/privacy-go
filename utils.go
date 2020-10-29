package privacy

import (
    "fmt"
    "github.com/CSCI-2390-Project/protobuf-go/proto"
    "github.com/CSCI-2390-Project/protobuf-go/reflect/protoreflect"
)

type Mode int

const (
    EncryptMode Mode = iota
    DecryptMode
)

// `recursiveEncrypt` examines all the field values of a message, and encrypts / decrypts them.
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

                // TODO: Replace with a call to privacy.Encrypt
                if mode == EncryptMode {
                    new_value, err := Encrypt(value.String())
                    if err != nil {
                        panic(err)
                    }
                    fmt.Println(fmt.Sprintf("Encrypted new_value is %+v", new_value))
                    protomessage.Set(fd, protoreflect.ValueOf(new_value))
                } else {
                    new_value := Decrypt(value.String())
                    fmt.Println(fmt.Sprintf("Decrypted new_value is %+v", new_value))
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
        recursiveCrypt(m, EncryptMode)
    }
    return err
}

// Marshal returns the wire-format encoding of m.
func Marshal(m proto.Message) ([]byte, error) {
    recursiveCrypt(m, DecryptMode)
    return proto.Marshal(m)
}
