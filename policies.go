package privacy

import (
	"encoding/json"
	"fmt"
	"github.com/go-stack/stack"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
)

type PolicyDocument struct {
	Policies []Policy `json:"Policies"`
}

type Policy struct {
	Message    string
	Field      string     `json:"Field"`
	Conditions Conditions `json:"Conditions"`
}

type Conditions struct {
	CopyConditions   *[]ConditionStatement `json:"Copying",omitEmpty`
	PrintConditions  *[]ConditionStatement `json:"Printing",omitEmpty`
	ModifyConditions *[]ConditionStatement `json:"Modifying",omitEmpty`
}

type ConditionStatement struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Pull policies from the stored policy file.
func loadPolicies(file_path string) (map[string]Conditions, error) {

	policies := make(map[string]Conditions)

	path, err := filepath.Abs(file_path)
	if err != nil {
		log.Errorf("Could not resolve provided filepath %s", file_path)
		return policies, nil
	}

	jsonFile, err := os.Open(path)
	defer jsonFile.Close()
	if err != nil {
		log.Errorf("Could not find file at provided filepath %s, treating policy document as empty", file_path)
		return policies, err
	}

	byteValue, _ := ioutil.ReadAll(jsonFile)
	document := PolicyDocument{}
	json.Unmarshal(byteValue, &document)

	for _, policy := range document.Policies {
		key := fmt.Sprintf("%s.%s", policy.Message, policy.Field)
		policies[key] = policy.Conditions
	}

	return policies, nil
}

func loadPoliciesFromEnvironmentVariable() (map[string]Conditions, error) {
	path := os.Getenv("GRPC_PRIVACY_POLICY_LOCATION")
	if len(path) == 0 {
		log.Warnf("GRPC_PRIVACY_POLICY_LOCATION not set, treating as if decryption is allowed in all conditions")
		return nil, nil
	}
	return loadPolicies(path)
}

// Do the task of verifying the policies themselves.
func isActionAllowed(messageName string, attributeName string, action string) bool {

	log.Info("Current call stack is %+n", stack.Trace())

	policies, err := loadPoliciesFromEnvironmentVariable()

	// if policies don't exist or is not found, assume everything is okay (shocking!)
	if policies == nil || len(policies) == 0 || err != nil {
		return true
	}

	key := fmt.Sprintf("%s.%s", messageName, attributeName)
	if _, ok := policies[key]; ok {
		switch action {
		case "Copying":
			return true
		case "Printing":
			return true
		case "Modifying":
			return true
		}
	}

	// if there is no policy for this key at all, the action is allowed.
	return true
}
