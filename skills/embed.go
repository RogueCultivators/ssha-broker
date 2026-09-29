// Package skills embeds the agent skill shipped with ssha.
package skills

import _ "embed"

// Name is the skill directory name.
const Name = "ssha-agent"

//go:embed ssha-agent/SKILL.md
var Content string
