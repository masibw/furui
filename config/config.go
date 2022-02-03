package config

import "os"

func IsDebug() bool {
	return os.Getenv("ENV") == "debug"
}

func IsTest() bool {
	return os.Getenv("ENV") == "test"
}
