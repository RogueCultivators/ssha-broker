package version

import "testing"

func TestNumbers(t *testing.T) {
	cases := []struct {
		in   string
		want [3]int
	}{
		{"1.2.3", [3]int{1, 2, 3}},
		{"v1.2.3", [3]int{1, 2, 3}},
		{"1.2.3-4-gabcdef", [3]int{1, 2, 3}},
		{"2.0.0-rc1", [3]int{2, 0, 0}},
		{"1.2", [3]int{1, 2, 0}},
		// A v prefix means a tag, and a tag does not need dots.
		{"v1", [3]int{1, 0, 0}},
		{"1.2rc3", [3]int{1, 2, 0}},
		{"0.0.0+git1726c7e", [3]int{0, 0, 0}},
		// A commit hash is not a version, even when it starts with digits.
		{"1726c7e", [3]int{0, 0, 0}},
		{"b12a023", [3]int{0, 0, 0}},
		{"", [3]int{0, 0, 0}},
		{"dev", [3]int{0, 0, 0}},
	}
	for _, c := range cases {
		if got := Numbers(c.in); got != c.want {
			t.Errorf("Numbers(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDisplay(t *testing.T) {
	cases := map[string]string{
		"1.2.3":            "1.2.3",
		"v1.2.3":           "1.2.3",
		"1.2.3-4-gabcdef":  "1.2.3",
		"1.2":              "1.2.0",
		"v1":               "1.0.0",
		"1.2rc3":           "1.2.0",
		"1726c7e":          "0.0.0",
		"dev":              "0.0.0",
		"0.0.0+git1726c7e": "0.0.0",
	}
	for in, want := range cases {
		if got := Display(in); got != want {
			t.Errorf("Display(%q) = %q, want %q", in, got, want)
		}
	}
}

// The shell and Go rules have to agree, or a package name and the version
// stamped inside it would disagree.
func TestIsVersion(t *testing.T) {
	yes := []string{"1.2.3", "v1.2.3", "v1", "1.2", "1.2rc3", "1.2.3-4-gabcdef", "0.0.0+git1726c7e"}
	no := []string{"1726c7e", "b12a023", "1", "dev", "", "  "}
	for _, v := range yes {
		if !IsVersion(v) {
			t.Errorf("IsVersion(%q) = false, want true", v)
		}
	}
	for _, v := range no {
		if IsVersion(v) {
			t.Errorf("IsVersion(%q) = true, want false", v)
		}
	}
}

func TestComma(t *testing.T) {
	cases := map[string]string{
		"1.2.3":   "1,2,3,0",
		"1.2rc3":  "1,2,0,0",
		"1726c7e": "0,0,0,0",
	}
	for in, want := range cases {
		if got := Comma(in); got != want {
			t.Errorf("Comma(%q) = %q, want %q", in, got, want)
		}
	}
}

// A Debian version has to begin with a digit, which is why Display never
// returns a commit hash.
func TestDisplayAlwaysStartsLikeAVersion(t *testing.T) {
	for _, in := range []string{"1726c7e", "b12a023", "dev", ""} {
		if got := Display(in); got[0] < '0' || got[0] > '9' {
			t.Errorf("Display(%q) = %q, which does not start with a digit", in, got)
		}
	}
}
