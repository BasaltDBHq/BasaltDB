package linkstest

import "github.com/google/uuid"

func PluginFile(id uuid.UUID) string { return "basalt-plugin-" + id.String() + ".txt" }
