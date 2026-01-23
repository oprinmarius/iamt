package wsman

import (
	"strings"
	"testing"
)

func TestParseChallenge(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantRealm string
		wantNonce string
		wantQop   string
		wantAlg   string
		wantErr   bool
	}{
		{
			name:      "standard comma-separated header",
			input:     `Digest realm="test@example.com", nonce="abc123", qop="auth", algorithm="MD5"`,
			wantRealm: "test@example.com",
			wantNonce: "abc123",
			wantQop:   "auth",
			wantAlg:   "MD5",
		},
		{
			name:      "space-separated fields (Intel NUC style)",
			input:     `Digest realm="Digest:12345678"  nonce="abcdefghij" qop="auth"`,
			wantRealm: "Digest:12345678",
			wantNonce: "abcdefghij",
			wantQop:   "auth",
			wantAlg:   "MD5",
		},
		{
			name:      "malformed qop with duplicates and extra whitespace",
			input:     `Digest realm="test" nonce="xyz" qop="auth auth-int  auth"`,
			wantRealm: "test",
			wantNonce: "xyz",
			wantQop:   "auth",
			wantAlg:   "MD5",
		},
		{
			name:      "qop with only auth-int returns empty",
			input:     `Digest realm="test" nonce="xyz" qop="auth-int"`,
			wantRealm: "test",
			wantNonce: "xyz",
			wantQop:   "",
			wantAlg:   "MD5",
		},
		{
			name:      "mixed comma and space separators",
			input:     `Digest realm="mixed", nonce="123"  qop="auth" algorithm="MD5"`,
			wantRealm: "mixed",
			wantNonce: "123",
			wantQop:   "auth",
			wantAlg:   "MD5",
		},
		{
			name:    "missing Digest prefix",
			input:   `Basic realm="test"`,
			wantErr: true,
		},
		{
			name:      "no qop specified defaults to empty",
			input:     `Digest realm="test", nonce="abc"`,
			wantRealm: "test",
			wantNonce: "abc",
			wantQop:   "",
			wantAlg:   "MD5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &challenge{}
			err := c.parseChallenge(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if c.Realm != tt.wantRealm {
				t.Errorf("Realm = %q, want %q", c.Realm, tt.wantRealm)
			}
			if c.Nonce != tt.wantNonce {
				t.Errorf("Nonce = %q, want %q", c.Nonce, tt.wantNonce)
			}
			if c.Qop != tt.wantQop {
				t.Errorf("Qop = %q, want %q", c.Qop, tt.wantQop)
			}
			if c.Algorithm != tt.wantAlg {
				t.Errorf("Algorithm = %q, want %q", c.Algorithm, tt.wantAlg)
			}
		})
	}
}

func TestNormalizeQop(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard auth",
			input: "auth",
			want:  "auth",
		},
		{
			name:  "auth-int only returns empty",
			input: "auth-int",
			want:  "",
		},
		{
			name:  "space-separated with auth",
			input: "auth auth-int",
			want:  "auth",
		},
		{
			name:  "malformed with duplicates and extra whitespace",
			input: "auth auth-int  auth",
			want:  "auth",
		},
		{
			name:  "comma-separated with auth",
			input: "auth,auth-int",
			want:  "auth",
		},
		{
			name:  "auth-int first then auth",
			input: "auth-int auth",
			want:  "auth",
		},
		{
			name:  "empty string returns empty",
			input: "",
			want:  "",
		},
		{
			name:  "unknown qop returns empty",
			input: "unknown",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeQop(tt.input)
			if got != tt.want {
				t.Errorf("normalizeQop(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestH(t *testing.T) {
	// MD5("") = d41d8cd98f00b204e9800998ecf8427e
	if got := h(""); got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("h(\"\") = %q, want d41d8cd98f00b204e9800998ecf8427e", got)
	}
	// MD5("test") = 098f6bcd4621d373cade4e832627b4f6
	if got := h("test"); got != "098f6bcd4621d373cade4e832627b4f6" {
		t.Errorf("h(\"test\") = %q, want 098f6bcd4621d373cade4e832627b4f6", got)
	}
}

func TestKD(t *testing.T) {
	// kd("secret", "data") = h("secret:data")
	expected := h("secret:data")
	if got := kd("secret", "data"); got != expected {
		t.Errorf("kd(\"secret\", \"data\") = %q, want %q", got, expected)
	}
}

func TestChallengeHA1(t *testing.T) {
	c := &challenge{
		Username: "admin",
		Realm:    "Digest:12345",
		Password: "password",
	}
	// HA1 = MD5(username:realm:password)
	expected := h("admin:Digest:12345:password")
	if got := c.ha1(); got != expected {
		t.Errorf("ha1() = %q, want %q", got, expected)
	}
}

func TestChallengeHA2(t *testing.T) {
	c := &challenge{}
	// HA2 = MD5(method:uri)
	expected := h("POST:/wsman")
	if got := c.ha2("POST", "/wsman"); got != expected {
		t.Errorf("ha2() = %q, want %q", got, expected)
	}
}

func TestChallengeResp(t *testing.T) {
	tests := []struct {
		name    string
		qop     string
		cnonce  string
		wantErr bool
	}{
		{
			name:    "qop auth with provided cnonce",
			qop:     "auth",
			cnonce:  "testcnonce",
			wantErr: false,
		},
		{
			name:    "qop auth without cnonce generates one",
			qop:     "auth",
			cnonce:  "",
			wantErr: false,
		},
		{
			name:    "empty qop uses simpler response",
			qop:     "",
			cnonce:  "",
			wantErr: false,
		},
		{
			name:    "unsupported qop returns error",
			qop:     "auth-int",
			cnonce:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &challenge{
				Username:   "admin",
				Realm:      "test",
				Password:   "password",
				Nonce:      "servernonce",
				Qop:        tt.qop,
				NonceCount: 0,
			}
			resp, err := c.resp("POST", "/wsman", tt.cnonce)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if resp == "" {
				t.Error("expected non-empty response")
			}
			if tt.qop == "auth" && tt.cnonce != "" && c.Cnonce != tt.cnonce {
				t.Errorf("Cnonce = %q, want %q", c.Cnonce, tt.cnonce)
			}
			if tt.qop == "auth" && tt.cnonce == "" && c.Cnonce == "" {
				t.Error("expected Cnonce to be generated")
			}
			if c.NonceCount != 1 {
				t.Errorf("NonceCount = %d, want 1", c.NonceCount)
			}
		})
	}
}

func TestChallengeAuthorize(t *testing.T) {
	tests := []struct {
		name      string
		challenge *challenge
		method    string
		uri       string
		wantErr   bool
		checkFunc func(t *testing.T, auth string)
	}{
		{
			name: "MD5 with qop auth",
			challenge: &challenge{
				Username:   "admin",
				Password:   "password",
				Realm:      "Digest:12345",
				Nonce:      "servernonce123",
				Algorithm:  "MD5",
				Qop:        "auth",
				NonceCount: 0,
			},
			method:  "POST",
			uri:     "/wsman",
			wantErr: false,
			checkFunc: func(t *testing.T, auth string) {
				if !strings.HasPrefix(auth, "Digest ") {
					t.Error("auth should start with 'Digest '")
				}
				requiredFields := []string{
					`username="admin"`,
					`realm="Digest:12345"`,
					`nonce="servernonce123"`,
					`uri="/wsman"`,
					`algorithm="MD5"`,
					"qop=auth",
					"nc=00000001",
				}
				for _, field := range requiredFields {
					if !strings.Contains(auth, field) {
						t.Errorf("auth missing %q: %s", field, auth)
					}
				}
			},
		},
		{
			name: "MD5 without qop",
			challenge: &challenge{
				Username:   "admin",
				Password:   "password",
				Realm:      "test",
				Nonce:      "nonce",
				Algorithm:  "MD5",
				Qop:        "",
				NonceCount: 0,
			},
			method:  "POST",
			uri:     "/wsman",
			wantErr: false,
			checkFunc: func(t *testing.T, auth string) {
				if strings.Contains(auth, "qop=") {
					t.Error("auth should not contain qop when Qop is empty")
				}
				if strings.Contains(auth, "nc=") {
					t.Error("auth should not contain nc when Qop is empty")
				}
				if strings.Contains(auth, "cnonce=") {
					t.Error("auth should not contain cnonce when Qop is empty")
				}
			},
		},
		{
			name: "with opaque",
			challenge: &challenge{
				Username:   "admin",
				Password:   "password",
				Realm:      "test",
				Nonce:      "nonce",
				Algorithm:  "MD5",
				Qop:        "auth",
				Opaque:     "opaque123",
				NonceCount: 0,
			},
			method:  "POST",
			uri:     "/wsman",
			wantErr: false,
			checkFunc: func(t *testing.T, auth string) {
				if !strings.Contains(auth, `opaque="opaque123"`) {
					t.Error("auth should contain opaque field")
				}
			},
		},
		{
			name: "non-MD5 algorithm fails",
			challenge: &challenge{
				Username:  "admin",
				Password:  "password",
				Realm:     "test",
				Nonce:     "nonce",
				Algorithm: "SHA256",
			},
			method:  "POST",
			uri:     "/wsman",
			wantErr: true,
		},
		{
			name: "auth-int qop fails",
			challenge: &challenge{
				Username:  "admin",
				Password:  "password",
				Realm:     "test",
				Nonce:     "nonce",
				Algorithm: "MD5",
				Qop:       "auth-int",
			},
			method:  "POST",
			uri:     "/wsman",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := tt.challenge.authorize(tt.method, tt.uri)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if tt.checkFunc != nil {
				tt.checkFunc(t, auth)
			}
		})
	}
}
