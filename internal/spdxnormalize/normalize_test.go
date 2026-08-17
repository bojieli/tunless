package spdxnormalize

import (
	"bytes"
	"testing"
)

func TestNormalizeIsDeterministic(t *testing.T) {
	input := []byte(`{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentNamespace": "https://example.invalid/random",
  "creationInfo": {"created": "2026-08-17T10:00:00Z", "creators": ["Tool: syft"]},
  "packages": [{"name": "dependency", "versionInfo": "1.2.3"}]
}`)
	want := []byte("{\n  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n  \"creationInfo\": {\n    \"created\": \"2023-11-14T22:13:20Z\",\n    \"creators\": [\n      \"Tool: syft\"\n    ]\n  },\n  \"documentNamespace\": \"https://github.com/bojieli/tunless/sbom/0.1.0/test.spdx.json\",\n  \"packages\": [\n    {\n      \"name\": \"dependency\",\n      \"versionInfo\": \"1.2.3\"\n    }\n  ],\n  \"spdxVersion\": \"SPDX-2.3\"\n}\n")

	first, err := Normalize(input, 1700000000, "https://github.com/bojieli/tunless/sbom/0.1.0/test.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Normalize(first, 1700000000, "https://github.com/bojieli/tunless/sbom/0.1.0/test.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, want) {
		t.Fatalf("normalized SPDX mismatch:\n%s", first)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("normalization is not idempotent")
	}
}

func TestNormalizeRejectsInvalidDocuments(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		epoch     int64
		namespace string
	}{
		{name: "json", input: `{`, namespace: "https://example.com/sbom"},
		{name: "epoch", input: `{"SPDXID":"SPDXRef-DOCUMENT","creationInfo":{}}`, epoch: -1, namespace: "https://example.com/sbom"},
		{name: "namespace", input: `{"SPDXID":"SPDXRef-DOCUMENT","creationInfo":{}}`, namespace: "relative"},
		{name: "identifier", input: `{"SPDXID":"other","creationInfo":{}}`, namespace: "https://example.com/sbom"},
		{name: "creation", input: `{"SPDXID":"SPDXRef-DOCUMENT"}`, namespace: "https://example.com/sbom"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Normalize([]byte(test.input), test.epoch, test.namespace); err == nil {
				t.Fatal("Normalize unexpectedly accepted invalid input")
			}
		})
	}
}
