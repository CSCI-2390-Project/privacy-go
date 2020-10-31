package privacy

import (
	"reflect"
	"testing"
)

func TestParsing(t *testing.T) {
	policies, err := loadPolicies("testing/files/example.json")
	if err != nil {
		t.Errorf("Encountered error opening the file %+v", err)
	}

	expected := map[string]Conditions{
		"HelloRequest.name": Conditions{
			CopyConditions:   &[]ConditionStatement{{Key: "message.name", Value: "Rodriguez"}},
			PrintConditions:  &[]ConditionStatement{},
			ModifyConditions: nil,
		},
		"HelloReply.message": Conditions{
			CopyConditions:   nil,
			PrintConditions:  nil,
			ModifyConditions: nil,
		},
	}

	for expected_key, expected_value := range expected {
		if found_value, ok := policies[expected_key]; ok {
			if !reflect.DeepEqual(found_value, expected_value) {
				t.Errorf("Expected %+v, got %+v", expected_value, found_value)
			}
		} else {
			t.Errorf("Expected %s to be in policies %+v", expected_key, policies)
		}
	}
}
