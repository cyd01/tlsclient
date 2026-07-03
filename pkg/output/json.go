package output

import (
	"encoding/json"
	"fmt"

	"github.com/cyd01/tlsclient/pkg/client"
)

// PrintJSON affiche le report en JSON.
func PrintJSON(c *client.Connection) error {

	b, err := json.MarshalIndent(c.Report, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(b))
	return nil
}
