package spdxnormalize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// Normalize replaces the two intentionally variable SPDX document fields and
// emits canonical, indented JSON. Package and file evidence is left unchanged.
func Normalize(input []byte, epoch int64, namespace string) ([]byte, error) {
	if epoch < 0 {
		return nil, fmt.Errorf("SOURCE_DATE_EPOCH must not be negative")
	}
	parsedNamespace, err := url.Parse(namespace)
	if err != nil || parsedNamespace.Scheme != "https" || parsedNamespace.Host == "" {
		return nil, fmt.Errorf("document namespace must be an absolute HTTPS URL")
	}

	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode SPDX JSON: %w", err)
	}
	if document["SPDXID"] != "SPDXRef-DOCUMENT" {
		return nil, fmt.Errorf("SPDXID is not SPDXRef-DOCUMENT")
	}
	creationInfo, ok := document["creationInfo"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("SPDX creationInfo object is missing")
	}
	creationInfo["created"] = time.Unix(epoch, 0).UTC().Format(time.RFC3339)
	document["documentNamespace"] = namespace

	output, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode SPDX JSON: %w", err)
	}
	return append(output, '\n'), nil
}
