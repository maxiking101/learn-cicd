package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	var errMalformed = errors.New("malformed authorization header")
	type result struct {
		value string
		err   error
	}
	tests := map[string]struct {
		header http.Header
		want   result
	}{
		"simple":                 {header: http.Header{"Authorization": []string{"ApiKey testkey"}}, want: result{"testkey", nil}},
		"no auth header":         {header: http.Header{}, want: result{"", auth.ErrNoAuthHeaderIncluded}},
		"maformed no value":      {header: http.Header{"Authorization": []string{"ApiKey"}}, want: result{"", errMalformed}},
		"malformed wrong prefix": {header: http.Header{"Authorization": []string{"SomePrefix testkey"}}, want: result{"", errMalformed}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := auth.GetAPIKey(tc.header)
			got := result{key, err}
			if got.value != tc.want.value {
				t.Fatalf("Expected value %v but got %v", tc.want.value, got.value)
			}
			if tc.want.err != nil {
				if got.err == nil {
					t.Fatalf("Expected error \"%v\" but got nil", tc.want.err)
				}
				if got.err.Error() != tc.want.err.Error() {
					t.Fatalf("Expected error \"%v\" but got \"%v\"", tc.want.err, got.err)
				}
			} else {
				if got.err != nil {
					t.Fatalf("Expected no error but got error: %v", tc.want.err)
				}
			}
		})
	}
}
