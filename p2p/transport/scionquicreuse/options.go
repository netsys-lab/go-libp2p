package scionquicreuse

type Option func(*ConnManager) error

// EnableMetrics enables Prometheus metrics collection.
func EnableMetrics() Option {
	return func(m *ConnManager) error {
		m.enableMetrics = true
		return nil
	}
}
