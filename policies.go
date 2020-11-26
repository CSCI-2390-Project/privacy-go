package privacy

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/reflect/protoreflect"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const environment_variable string = "GRPC_PRIVACY_POLICY_LOCATION"

var loaded_policies map[string]Conditions

// run on library import
func init() {
	refreshPolicies()
}

type PolicyDocument struct {
	Policies []Policy `json:"Policies"`
}

type Policy struct {
	Message    string     `json:"Message"`
	Field      string     `json:"Field"`
	Conditions Conditions `json:"Conditions"`
}

type Conditions struct {
	CopyConditions   *[]ConditionStatement `json:"Copying",omitEmpty`
	PrintConditions  *[]ConditionStatement `json:"Printing",omitEmpty`
	ModifyConditions *[]ConditionStatement `json:"Modifying",omitEmpty`
}

type ConditionStatement struct {
	Allowed bool   `json:"allowed"`
	If      string `json:"if"`
}

// Pull policies from the stored policy file.
func loadPolicies(file_path string) (map[string]Conditions, error) {

	path, err := filepath.Abs(file_path)
	if err != nil {
		log.Errorf("Could not resolve provided filepath %s", file_path)
		return nil, err
	}

	jsonFile, err := os.Open(path)
	defer jsonFile.Close()
	if err != nil {
		log.Errorf("Could not find file at provided filepath %s", file_path)
		return nil, err
	}

	byteValue, _ := ioutil.ReadAll(jsonFile)
	document := PolicyDocument{}
	json.Unmarshal(byteValue, &document)

	policies := make(map[string]Conditions)
	for _, policy := range document.Policies {
		key := fmt.Sprintf("%s.%s", strings.Title(policy.Message), strings.Title(policy.Field))
		policies[key] = policy.Conditions
	}

	return policies, nil
}

// Fetches the policies and stores them in memory. Called once in init().
// Can be called in testing code as well.
func refreshPolicies() {
	policies, err := loadPoliciesFromEnvironmentVariable()
	if err != nil {
		log.Warnf("Error fetching policies. All actions will be allowed and no policies will be checked.")
	}
	loaded_policies = policies
}

func loadPoliciesFromEnvironmentVariable() (map[string]Conditions, error) {
	path := os.Getenv(environment_variable)
	if len(path) == 0 {
		log.Warnf("%s not set", environment_variable)
		return nil, nil
	}
	return loadPolicies(path)
}

// Do the task of verifying the policies themselves.
func isActionAllowed(messageName protoreflect.Name, attributeName protoreflect.Name, act action, trace []string) bool {

	log.Debugf("Received %s, %s, %v, %+v", messageName, attributeName, act, trace)
	log.Debugf("Policies file was parsed as %+v", loaded_policies)

	// if policies don't exist or is empty, assume action is allowed
	// for backwards-compatibility purposes.
	if loaded_policies == nil || len(loaded_policies) == 0 {
		return true
	}

	key := fmt.Sprintf("%s.%s", strings.Title(string(messageName)), strings.Title(string(attributeName)))
	log.Debugf("Converting %s, %s to %s", messageName, attributeName, key)

	if conditions, ok := loaded_policies[key]; ok {

		log.Debugf("Found all conditions for %s: %+v", key, conditions)

		chosen_condition := conditions.CopyConditions
		switch act {
		case copying:
			chosen_condition = conditions.CopyConditions
		case printing:
			chosen_condition = conditions.PrintConditions
		case modifying:
			chosen_condition = conditions.ModifyConditions
		}

		log.Debugf("Because %+v was chosen for action, using specific condition for that action: %+v", key, chosen_condition)

		if chosen_condition == nil {
			return true
		}

		for _, condition := range *chosen_condition {
			log.Debugf("Considering %+v", condition)
			if matches(condition.If, trace) {
				log.Debugf("Accepted %+v", condition)
				return condition.Allowed
			}
		}

		return false
	}

	// if there is no policy for this key at all, the action is allowed.
	log.Debugf("No corresponding policy for %s in policy file at GRPC_PRIVACY_POLICY_LOCATION was found", key)
	return true
}

// match an `if` to the actual current call stack.
func matches(conditionspec string, trace []string) bool {
	order := strings.Split(conditionspec, "<")
	if len(order) == 0 {
		return false
	}

	index := 0
	for _, function := range trace {
		if function == strings.TrimSpace(order[index]) {
			index += 1
			if index == len(order) {
				return true
			}
		}
	}

	return false
}
