package serverv1

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Number decodes a JSON number or a numeric string. An empty string or null
// decodes as 0, since that is how the panel's custom_config template leaves
// unset fields.
type Number float64

func (n *Number) UnmarshalJSON(content []byte) error {
	if string(content) == "null" {
		*n = 0
		return nil
	}
	var stringValue string
	if json.Unmarshal(content, &stringValue) == nil {
		stringValue = strings.TrimSpace(stringValue)
		if stringValue == "" {
			*n = 0
			return nil
		}
		value, err := strconv.ParseFloat(stringValue, 64)
		if err != nil {
			return err
		}
		*n = Number(value)
		return nil
	}
	return json.Unmarshal(content, (*float64)(n))
}
