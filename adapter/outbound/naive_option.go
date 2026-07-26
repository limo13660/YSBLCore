package outbound

type NaiveOption struct {
	BasicOption
	Name                     string            `proxy:"name"`
	Server                   string            `proxy:"server"`
	Port                     int               `proxy:"port"`
	Username                 string            `proxy:"username,omitempty"`
	Password                 string            `proxy:"password,omitempty"`
	SNI                      string            `proxy:"sni,omitempty"`
	UDP                      bool              `proxy:"udp,omitempty"`
	UDPOverTCP               bool              `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion        int               `proxy:"udp-over-tcp-version,omitempty"`
	InsecureConcurrency      int               `proxy:"insecure-concurrency,omitempty"`
	ExtraHeaders             map[string]string `proxy:"extra-headers,omitempty"`
	ReceiveWindow            uint64            `proxy:"recv-window,omitempty"`
	Certificate              string            `proxy:"certificate,omitempty"`
	ECHOpts                  ECHOptions        `proxy:"ech-opts,omitempty"`
	QUIC                     bool              `proxy:"quic,omitempty"`
	QUICCongestionController string            `proxy:"quic-congestion-controller,omitempty"`
	QUICSessionReceiveWindow uint64            `proxy:"quic-session-recv-window,omitempty"`
}
