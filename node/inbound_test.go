package node

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

// A silent mismap here would change which site the node impersonates, so the
// mapping is pinned rather than assumed.
func TestParseWildcardSNI(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    option.WildcardSNI
		wantErr bool
	}{
		{in: "", want: option.ShadowTLSWildcardSNIOff},
		{in: "off", want: option.ShadowTLSWildcardSNIOff},
		{in: "authed", want: option.ShadowTLSWildcardSNIAuthed},
		{in: "all", want: option.ShadowTLSWildcardSNIAll},
		{in: "  ALL  ", want: option.ShadowTLSWildcardSNIAll},
		{in: "Authed", want: option.ShadowTLSWildcardSNIAuthed},
		{in: "yes", wantErr: true},
		{in: "true", wantErr: true},
	} {
		got, err := parseWildcardSNI(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseWildcardSNI(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseWildcardSNI(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseWildcardSNI(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
