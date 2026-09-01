package config

import conf "github.com/birukbelay/gocmn/src/config"

type EnvConfig struct {
	// Env string `koanf:"ENV"`

	ServerPort string `koanf:"SERVER_PORT"`
	ServerHost string `koanf:"SERVER_HOST"`

	SqlDbConfig conf.SqlDbConfig `koanf:",squash"`
	conf.JwtVar




	conf.KeyValConfig
	FireBasePath string `koanf:"FIREBASE_SERVICE_ACCOUNT_PATH"`

	//test related
	TestDbName                  string `koanf:"TEST_DB_NAME"`
	UseTestContainers           string `koanf:"USE_TEST_CONTAINERS"`
	// WebLink                     string `koanf:"WEB_LINK"`
}