//go:build linux

package enforce

type connectBackend struct{}

func newConnectBackend() backend {
	return connectBackend{}
}

func expectedConnectBackendName() string {
	return "cgroup-connect"
}

func (connectBackend) Name() string {
	return expectedConnectBackendName()
}

func (connectBackend) Run(request Request) (Result, error) {
	return unsupportedResult(request), ErrUnsupported
}
