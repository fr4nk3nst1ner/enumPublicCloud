package cloud

import (
	"log"
	"os"
)

// LogConfig represents the configuration for logging
type LogConfig struct {
	Level string
}

// Logger instances
var (
	InfoLogger  *log.Logger
	ErrorLogger *log.Logger
	DebugLogger *log.Logger
)

// InitLogger initializes the loggers
func InitLogger(config LogConfig) {
	InfoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	ErrorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)
	
	// Only enable debug logger if level is DEBUG
	if config.Level == "DEBUG" {
		DebugLogger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime)
	} else {
		DebugLogger = log.New(os.Stdout, "DEBUG: ", 0)
		DebugLogger.SetOutput(nil)
	}
} 