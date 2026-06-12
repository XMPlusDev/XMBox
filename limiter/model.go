package limiter

// RedisConfig holds Redis connection parameters for the global IP-limiter.
type RedisConfig struct {
	Enable   bool   `mapstructure:"Enable"`
	Network  string `mapstructure:"Network"` // "tcp" or "unix"
	Addr     string `mapstructure:"Addr"`
	Username string `mapstructure:"Username"`
	Password string `mapstructure:"Password"`
	DB       int    `mapstructure:"DB"`
	Timeout  int    `mapstructure:"Timeout"` // seconds for context deadlines
}
