package privacy

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	//"google.golang.org/protobuf/proto"
	//"google.golang.org/protobuf/reflect/protoreflect"
)

// load the policy
func load_policies(file_path string) (map[string]Conditions, error) {
	path, err := filepath.Abs(file_path)
	if err != nil {
		return nil, err
	}
	jsonFile, err := os.Open(path)
	// if we os.Open returns an error then handle it
	if err != nil {
		//log.Printf(err)
		return nil, err
	}
	defer jsonFile.Close()

	log.Printf("Successfully Opened %+v", file_path)
	// read our opened xmlFile as a byte array.
	byteValue, _ := ioutil.ReadAll(jsonFile)

	result := PolicyDocument{}

	json.Unmarshal(byteValue, &result)

	log.Printf("this should be the result %+v", result)

	mymap := make(map[string]Conditions)

	for _, policy := range result.Policies {
		mymap[policy.Field] = policy.Conditions
	}

	return mymap, nil
}

type PolicyDocument struct {
	Policies []Policy `json:"Policy"`
}

type Policy struct {
	Field      string     `json:"Field"`
	Conditions Conditions `json:"Conditions"`
}
type Conditions struct {
	CopyConditions  [][]string `json:"Copying"`
	PrintConditions [][]string `json:"Printing"`
}
