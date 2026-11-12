package setupcode

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckNoDuplicateKeys(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		json string
		dup  bool
	}{
		"flat":                         {`{"a":1,"b":2}`, false},
		"same key in sibling objects":  {`{"a":{"k":1},"b":{"k":2}}`, false},
		"same key at different depths": {`{"k":{"k":{"k":1}}}`, false},
		"objects in an array":          {`{"a":[{"k":1},{"k":2}]}`, false},
		"top level":                    {`{"a":1,"a":2}`, true},
		"escaped":                      {"{\"a\":1,\"\\u0061\":2}", true},
		"depth two":                    {`{"a":{"b":1,"b":2}}`, true},
		"depth four":                   {`{"a":{"b":{"c":{"d":1,"e":[],"d":{}}}}}`, true},
		"in an array of objects":       {`{"a":[{"k":1},{"k":2,"x":null,"k":3}]}`, true},
		"after a nested object closes": {`{"a":{"b":1},"c":[1,{"d":2}],"a":3}`, true},
	} {
		err := checkNoDuplicateKeys([]byte(c.json))
		if c.dup {
			require.Error(t, err, name)
			continue
		}
		require.NoError(t, err, name)
	}
}
