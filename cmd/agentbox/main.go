// Command agentbox is the host-side launcher/CLI.
package main

import (
	"fmt"

	"github.com/Oleg-Imanilov/agent-box/internal/version"
)

func main() {
	fmt.Println(version.String("agentbox"))
}
