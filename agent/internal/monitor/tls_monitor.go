package monitor

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

// TLSAlert represents a TLS-related security finding.
type TLSAlert struct {
	AlertType   string    `json:"alert_type"` // expired_cert, weak_cipher, weak_protocol, self_signed, missing_san
	Host        string    `json:"host"`
	Port        string    `json:"port"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	CertSubject string    `json:"cert_subject,omitempty"`
	CertExpiry  time.Time `json:"cert_expiry,omitempty"`
	Protocol    uint16    `json:"protocol,omitempty"`
	CipherSuite uint16   `json:"cipher_suite,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// TLSMonitor inspects TLS connections for security issues.
type TLSMonitor struct {
	alerts chan TLSAlert
}

func NewTLSMonitor() *TLSMonitor {
	return &TLSMonitor{
		alerts: make(chan TLSAlert, 256),
	}
}

func (m *TLSMonitor) Alerts() <-chan TLSAlert {
	return m.alerts
}

// InspectConnection performs a TLS handshake and analyzes the connection parameters.
// This is used when the agent observes a new outbound TLS connection.
func (m *TLSMonitor) InspectConnection(host, port string) {
	addr := net.JoinHostPort(host, port)
	now := time.Now()

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return // Can't connect — not a TLS issue we can detect
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Check protocol version
	if state.Version < tls.VersionTLS12 {
		m.emitAlert(TLSAlert{
			AlertType:   "weak_protocol",
			Host:        host,
			Port:        port,
			Severity:    "high",
			Description: "TLS version below 1.2 detected",
			Protocol:    state.Version,
			Timestamp:   now,
		})
	}

	// Check cipher suite
	if isWeakCipher(state.CipherSuite) {
		m.emitAlert(TLSAlert{
			AlertType:   "weak_cipher",
			Host:        host,
			Port:        port,
			Severity:    "medium",
			Description: "Weak cipher suite in use",
			CipherSuite: state.CipherSuite,
			Timestamp:   now,
		})
	}

	// Check certificates
	for _, cert := range state.PeerCertificates {
		if cert.IsCA {
			continue
		}

		// Expired certificate
		if cert.NotAfter.Before(now) {
			m.emitAlert(TLSAlert{
				AlertType:   "expired_cert",
				Host:        host,
				Port:        port,
				Severity:    "critical",
				Description: "Expired TLS certificate",
				CertSubject: cert.Subject.CommonName,
				CertExpiry:  cert.NotAfter,
				Timestamp:   now,
			})
		} else if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
			m.emitAlert(TLSAlert{
				AlertType:   "expiring_cert",
				Host:        host,
				Port:        port,
				Severity:    "high",
				Description: "TLS certificate expires within 30 days",
				CertSubject: cert.Subject.CommonName,
				CertExpiry:  cert.NotAfter,
				Timestamp:   now,
			})
		}

		// Self-signed
		if cert.Issuer.CommonName == cert.Subject.CommonName && !cert.IsCA {
			m.emitAlert(TLSAlert{
				AlertType:   "self_signed",
				Host:        host,
				Port:        port,
				Severity:    "medium",
				Description: "Self-signed certificate detected",
				CertSubject: cert.Subject.CommonName,
				CertExpiry:  cert.NotAfter,
				Timestamp:   now,
			})
		}

		// Weak key
		if cert.PublicKeyAlgorithm == x509.RSA {
			if key, ok := cert.PublicKey.(interface{ Size() int }); ok {
				if key.Size()*8 < 2048 {
					m.emitAlert(TLSAlert{
						AlertType:   "weak_key",
						Host:        host,
						Port:        port,
						Severity:    "high",
						Description: "RSA key size below 2048 bits",
						CertSubject: cert.Subject.CommonName,
						Timestamp:   now,
					})
				}
			}
		}

		// Missing Subject Alternative Names
		if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
			m.emitAlert(TLSAlert{
				AlertType:   "missing_san",
				Host:        host,
				Port:        port,
				Severity:    "low",
				Description: "Certificate has no Subject Alternative Names",
				CertSubject: cert.Subject.CommonName,
				Timestamp:   now,
			})
		}
	}
}

func (m *TLSMonitor) emitAlert(alert TLSAlert) {
	select {
	case m.alerts <- alert:
	default:
	}
}

// isWeakCipher checks if a cipher suite is considered weak.
func isWeakCipher(suite uint16) bool {
	weak := map[uint16]bool{
		tls.TLS_RSA_WITH_RC4_128_SHA:                true,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           true,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          true,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        true,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:          true,
	}
	return weak[suite]
}
