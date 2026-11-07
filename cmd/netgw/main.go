// Command netgw is the network gateway (HTTP/CONNECT proxy and DNS resolver).
package main

import (
	"fmt"

	"github.com/Oleg-Imanilov/agent-box/internal/version"
)

func main() {
	fmt.Println(version.String("agentbox-netgw"))
}
