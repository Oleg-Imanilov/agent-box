// Command mcpgw is the MCP gateway.
package main

import (
	"fmt"

	"github.com/Oleg-Imanilov/agent-box/internal/version"
)

func main() {
	fmt.Println(version.String("agentbox-mcpgw"))
}
