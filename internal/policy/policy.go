package policy

import (
	"net/netip"
	"path/filepath"
	"strings"
)

type Options struct {
	DeniedWritePrefixes []string
	DeniedConnectCIDRs  []string
}

type Policy struct {
	DeniedWritePrefixes []string
	DeniedConnectCIDRs  []string

	deniedConnectPrefixes []netip.Prefix
}

func New(options Options) (Policy, error) {
	p := Policy{
		DeniedWritePrefixes: append([]string(nil), options.DeniedWritePrefixes...),
		DeniedConnectCIDRs:  append([]string(nil), options.DeniedConnectCIDRs...),
	}
	for _, raw := range options.DeniedConnectCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return Policy{}, err
		}
		p.deniedConnectPrefixes = append(p.deniedConnectPrefixes, prefix)
	}
	return p, nil
}

func (p Policy) DeniesWrite(path string) bool {
	clean := filepath.Clean(path)
	for _, prefix := range p.DeniedWritePrefixes {
		cleanPrefix := filepath.Clean(prefix)
		if clean == cleanPrefix || strings.HasPrefix(clean, cleanPrefix+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (p Policy) DeniesConnect(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	for _, prefix := range p.deniedConnectPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func (p Policy) ConnectPrefixes() []netip.Prefix {
	return append([]netip.Prefix(nil), p.deniedConnectPrefixes...)
}

func (p Policy) Empty() bool {
	return len(p.DeniedWritePrefixes) == 0 && len(p.DeniedConnectCIDRs) == 0
}
