package privacy

import (
	"google.golang.org/protobuf/reflect/protoreflect"
	"os"
	"reflect"
	"testing"
)

func setupExamplePolicy(t *testing.T, filepath string) func(t *testing.T) {
	t.Logf("Setting %s", environment_variable)
	os.Setenv(environment_variable, filepath)
	refreshPolicies()
	return func(t *testing.T) {
		t.Logf("Unsetting %s", environment_variable)
		os.Unsetenv(environment_variable)
		refreshPolicies()
	}
}

func TestParsing(t *testing.T) {

	policies, err := loadPolicies("testing/files/example.json")
	if err != nil {
		t.Errorf("Encountered error opening the file %+v", err)
	}

	expected := map[string]Conditions{
		"HelloRequest.Name": Conditions{
			CopyConditions:   &[]ConditionStatement{{Allowed: true, If: "HelloRequest.GetName < main.main"}},
			PrintConditions:  &[]ConditionStatement{},
			ModifyConditions: nil,
		},
		"HelloReply.Message": Conditions{
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

func TestIsMatchesPositionIndependent(t *testing.T) {

	if !matches("me", []string{"me"}) {
		t.Errorf("Expected `me` to match `[me]`")
	}

	if !matches("me", []string{"you", "me"}) {
		t.Errorf("Expected `me` to match `[you, me]`")
	}

	if !matches("you", []string{"me", "you"}) {
		t.Errorf("Expected `you` to match `[me, you]`")
	}

	if matches("us", []string{"me", "you"}) {
		t.Errorf("Did not expect `us` to match `[me, you]`")
	}

	if matches("me < us", []string{"me", "you"}) {
		t.Errorf("Did not expect `me < us` to match `[me, you]`")
	}

	if !matches("me < us", []string{"me", "us", "you"}) {
		t.Errorf("Expected `me < us` to match `[me, us, you]`")
	}

	if !matches("me < us < you", []string{"me", "us", "you"}) {
		t.Errorf("Expected `me < us < you` to match `[me, us, you]`")
	}

	if !matches("me < you", []string{"me", "us", "you"}) {
		t.Errorf("Expected `me < you` to match `[me, us, you]`")
	}

	if !matches("me < you", []string{"me", "us", "them", "you"}) {
		t.Errorf("Expected `me < you` to match `[me, us,, them, you]`")
	}

	if matches("me < you", []string{"you", "us", "them", "me"}) {
		t.Errorf("Did not expect `me < you` to match `[you, us, them, me]`")
	}

	if matches("", []string{"me", "us", "you"}) {
		t.Errorf("Did not expected `us` to match `[me, us, you]`")
	}

	if !matches("me", []string{"me", "me", "me"}) {
		t.Errorf("Expected `me` to match `[me, me, me]`")
	}

	if matches("me < me < me < me", []string{"me", "me", "me"}) {
		t.Errorf("Did not expect `me < me < me < me` to match `[me, me, me]`")
	}

	if !matches("me < us", []string{"me", "you", "you", "us"}) {
		t.Errorf("Expected `me < us` to match `[me, you, you, us]`")
	}
}

func TestIsActionAllowedFunction(t *testing.T) {
	teardownFunc := setupExamplePolicy(t, "testing/files/example.json")
	defer teardownFunc(t)

	cases := []struct {
		message    protoreflect.Name
		field      protoreflect.Name
		act        action
		trace      []string
		shouldPass bool
	}{{
		"HelloRequest",
		"name",
		copying,
		[]string{"HelloRequest.GetName", "main.main"},
		true,
	}, {
		"HelloRequest",
		"name",
		printing,
		[]string{"HelloRequest.GetName", "main.main"},
		false,
	}, {
		"HelloRequest",
		"name",
		modifying,
		[]string{"HelloRequest.GetName", "main.main"},
		true,
	}, {
		"HelloRequest",
		"name",
		copying,
		[]string{"main.main"},
		false,
	}, {
		"HelloRequest",
		"name",
		printing,
		[]string{"main.main"},
		false,
	}, {
		"HelloRequest",
		"name",
		modifying,
		[]string{"main.main"},
		true,
	}, {
		"HelloRequest",
		"foo",
		copying,
		[]string{"HelloRequest.GetName", "main.main"},
		true,
	}, {
		"HelloRequest",
		"foo",
		printing,
		[]string{"HelloRequest.GetName", "main.main"},
		true,
	}, {
		"HelloRequest",
		"foo",
		modifying,
		[]string{"HelloRequest.GetName", "main.main"},
		true,
	}, {
		"HelloRequest2",
		"name",
		copying,
		[]string{"HelloRequest.GetName", "main.main"},
		true,
	}, {
		"HelloRequest2",
		"name",
		printing,
		[]string{"HelloRequest.GetName", "main.main"},
		true,
	}, {
		"HelloRequest2",
		"name",
		modifying,
		[]string{"HelloRequest.GetName", "main.main"},
		true,
	}}

	for _, caseof := range cases {
		if isActionAllowed(caseof.message, caseof.field, caseof.act, caseof.trace) != caseof.shouldPass {
			t.Errorf("Expected case %v to pass, but did not", caseof)
		}
	}
}
