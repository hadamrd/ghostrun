//go:build !linux

package enforce

func newConnectBackend() backend {
	return unsupportedBackend{}
}

func expectedConnectBackendName() string {
	return "unsupported"
}
