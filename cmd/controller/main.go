// Command controller is the policy, audit and API service (runs in a container).
package main

import (
	"fmt"

	"github.com/Oleg-Imanilov/agent-box/internal/version"
)

func main() {
	fmt.Println(version.String("agentbox-controller"))
}
