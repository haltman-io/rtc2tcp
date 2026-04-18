package config

var (
	DefaultBrokerURL = ""
	Version          = "dev"
	Commit           = "unknown"
)

type BuildInfo struct {
	DefaultBrokerURL string
	Version          string
	Commit           string
}

func CurrentBuild() BuildInfo {
	return BuildInfo{
		DefaultBrokerURL: DefaultBrokerURL,
		Version:          Version,
		Commit:           Commit,
	}
}
