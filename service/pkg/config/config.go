package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

type Config struct {
	Server     ServerConfig     `mapstructure:"server" validate:"required"`
	Database   DatabaseConfig   `mapstructure:"database" validate:"required"`
	ClickHouse ClickHouseConfig `mapstructure:"clickhouse"`
	Neo4j      Neo4jConfig      `mapstructure:"neo4j"`
	Redis      RedisConfig      `mapstructure:"redis" validate:"required"`
	Kafka      KafkaConfig      `mapstructure:"kafka"`
	S3         S3Config         `mapstructure:"s3"`
	Telemetry  TelemetryConfig  `mapstructure:"telemetry" validate:"required"`
	Internal   InternalConfig   `mapstructure:"internal"`
	Security   SecurityConfig   `mapstructure:"security"`
}

// SecurityConfig holds the inbound user-JWT validation settings. Callers of the
// HTTP surface present an authorization: Bearer <jwt>; it is validated against
// identity-service's JWKS so the request's (user, org) identity comes from
// signed claims rather than from spoofable headers. Matches the field + env
// names catalog/delivery/permission use (APP_AUTH_JWKS_URL / APP_AUTH_JWT_ISSUER,
// already shipped in the tracked .env.shared).
type SecurityConfig struct {
	// JWKSURL is the identity-service JWKS endpoint used to validate inbound
	// user JWTs. Empty is a boot failure — see app.NewServer.
	JWKSURL string `mapstructure:"jwks_url"`
	// JWTIssuer is the expected iss claim on inbound user JWTs.
	JWTIssuer string `mapstructure:"jwt_issuer"`
}

// InternalConfig holds the shared platform-wide internal service token used for
// service-to-service (x-api-key) auth. Empty in dev/homelab trusts in-cluster
// traffic; a set value is enforced (constant-time compare). Same
// APP_INTERNAL_SERVICE_TOKEN key catalog/codegen validate.
type InternalConfig struct {
	ServiceToken string `mapstructure:"service_token"`
}

type ServerConfig struct {
	Port         string        `mapstructure:"port" validate:"required,numeric"`
	GRPCPort     int           `mapstructure:"grpc_port"`
	Environment  string        `mapstructure:"environment" validate:"required,oneof=development staging production"`
	LogLevel     string        `mapstructure:"log_level" validate:"required,oneof=debug info warn error"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" validate:"required"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" validate:"required"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout" validate:"required"`
}

type DatabaseConfig struct {
	Host         string        `mapstructure:"host" validate:"required"`
	Port         string        `mapstructure:"port" validate:"required,numeric"`
	User         string        `mapstructure:"user" validate:"required"`
	Password     string        `mapstructure:"password"`
	Name         string        `mapstructure:"name" validate:"required"`
	SSLMode      string        `mapstructure:"ssl_mode" validate:"required,oneof=disable require verify-full"`
	MaxOpenConns int           `mapstructure:"max_open_conns" validate:"required,min=1"`
	MaxIdleConns int           `mapstructure:"max_idle_conns" validate:"required,min=1"`
	MaxLifetime  time.Duration `mapstructure:"max_lifetime" validate:"required"`
}

type ClickHouseConfig struct {
	Addr     string `mapstructure:"addr"`
	Database string `mapstructure:"database"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
}

type Neo4jConfig struct {
	URI      string `mapstructure:"uri"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
}

type RedisConfig struct {
	Addr     string `mapstructure:"addr" validate:"required"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type KafkaConfig struct {
	Brokers     []string `mapstructure:"brokers"`
	TopicPrefix string   `mapstructure:"topic_prefix"`
	ClientID    string   `mapstructure:"client_id"`
	GroupID     string   `mapstructure:"group_id"`
}

type S3Config struct {
	Endpoint        string `mapstructure:"endpoint"`
	Bucket          string `mapstructure:"bucket"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key"`
	Region          string `mapstructure:"region"`
	UseSSL          bool   `mapstructure:"use_ssl"`
}

type TelemetryConfig struct {
	ServiceName  string `mapstructure:"service_name" validate:"required"`
	OTLPEndpoint string `mapstructure:"otlp_endpoint" validate:"required"`
	MetricPort   string `mapstructure:"metric_port" validate:"required,numeric"`
}

func Load() (*Config, error) {
	v := viper.New()

	v.AddConfigPath("configs")
	v.AddConfigPath(".")
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	v.SetEnvPrefix("APP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Database bindings
	_ = v.BindEnv("database.host", "APP_DATABASE_HOST")
	_ = v.BindEnv("database.port", "APP_DATABASE_PORT")
	_ = v.BindEnv("database.user", "APP_DATABASE_USER")
	_ = v.BindEnv("database.password", "APP_DATABASE_PASSWORD")
	_ = v.BindEnv("database.name", "APP_DATABASE_NAME")

	// ClickHouse bindings
	_ = v.BindEnv("clickhouse.addr", "APP_CLICKHOUSE_ADDR")
	_ = v.BindEnv("clickhouse.database", "APP_CLICKHOUSE_DATABASE")
	_ = v.BindEnv("clickhouse.user", "APP_CLICKHOUSE_USER")
	_ = v.BindEnv("clickhouse.password", "APP_CLICKHOUSE_PASSWORD")

	// Neo4j bindings
	_ = v.BindEnv("neo4j.uri", "APP_NEO4J_URI")
	_ = v.BindEnv("neo4j.user", "APP_NEO4J_USER")
	_ = v.BindEnv("neo4j.password", "APP_NEO4J_PASSWORD")

	// Kafka bindings
	_ = v.BindEnv("kafka.brokers", "APP_KAFKA_BROKERS")
	_ = v.BindEnv("kafka.topic_prefix", "APP_KAFKA_TOPIC_PREFIX")
	_ = v.BindEnv("kafka.client_id", "APP_KAFKA_CLIENT_ID")
	_ = v.BindEnv("kafka.group_id", "APP_KAFKA_GROUP_ID")

	// S3 bindings
	_ = v.BindEnv("s3.endpoint", "APP_S3_ENDPOINT")
	_ = v.BindEnv("s3.bucket", "APP_S3_BUCKET")
	_ = v.BindEnv("s3.access_key_id", "APP_S3_ACCESS_KEY_ID")
	_ = v.BindEnv("s3.secret_access_key", "APP_S3_SECRET_ACCESS_KEY")

	// gRPC port binding
	_ = v.BindEnv("server.grpc_port", "APP_GRPC_PORT")
	v.SetDefault("server.grpc_port", 50051)

	// Shared internal service-token (x-api-key) binding
	_ = v.BindEnv("internal.service_token", "APP_INTERNAL_SERVICE_TOKEN")

	// Inbound user-JWT validation. Same in-cluster identity JWKS endpoint +
	// issuer catalog/foundry default to, so a clean deploy validates tokens with
	// no env set at all; .env.shared supplies the same pair explicitly.
	_ = v.BindEnv("security.jwks_url", "APP_AUTH_JWKS_URL")
	_ = v.BindEnv("security.jwt_issuer", "APP_AUTH_JWT_ISSUER")
	v.SetDefault("security.jwks_url", "http://identity-service:8080/.well-known/jwks.json")
	v.SetDefault("security.jwt_issuer", "identity-service")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		fmt.Println("Warning: config file not found, relying on environment variables")
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := newValidator().Struct(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// newValidator builds the config validator with WithRequiredStructEnabled so
// that `required` tags on the nested struct fields (Server/Database/Redis/
// Telemetry) are actually enforced. Without the option, go-playground/validator
// treats a `required` tag on a non-pointer struct field as a silent no-op — the
// tag looks like a control but does nothing. This matches platform-kit's own
// validation package, which already sets the option.
func newValidator() *validator.Validate {
	return validator.New(validator.WithRequiredStructEnabled())
}

func (c *Config) GetDatabaseURL() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.User,
		c.Database.Password,
		c.Database.Name,
		c.Database.SSLMode,
	)
}

func (c *Config) GetDatabaseDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Name,
		c.Database.SSLMode,
	)
}
