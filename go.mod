module github.com/CSCI-2390-Project/privacy-go

go 1.15

require (
	github.com/fernet/fernet-go v0.0.0-20191111064656-eff2850e6001
	github.com/go-stack/stack v1.8.0
	github.com/sirupsen/logrus v1.7.0
	google.golang.org/protobuf v1.23.1-0.20200526195155-81db48ad09cc
)

replace google.golang.org/protobuf => github.com/CSCI-2390-Project/protobuf-go v1.25.1-0.20201029202626-b6c08e03c161
