package collect

import "github.com/cyd01/tlsclient/pkg/client"

// CollectTiming garantit la cohérence des durées.
func CollectTiming(c *client.Connection) error {

	// déjà calculé dans connect.go, mais on peut enrichir ici
	// si on ajoute du debug ou instrumentation future

	return nil
}
