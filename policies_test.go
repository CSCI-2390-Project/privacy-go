package privacy

import (
	"testing"
)

func TestCanReadFile(t *testing.T) {
	_, err := load_policies("policy_back.json")
	if err != nil {
		t.Error("Oh no I could not open the file")
	}
}

func Testprint(t *testing.T) {
	policydoc, err := load_policies("policy_back.json")
	t.Logf("I am not empty: %+v", policydoc)
	if err != nil {
		t.Error("Something happened")
	}
}
