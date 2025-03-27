package discover

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type localJwksConfig struct {
	Issuer string
	File   string
	TTL    time.Duration
}

// LocalJwks uses locally available JWKS information where possible.
//
// It is configured using a text file with lines like the following:
//
//	ISSUER { KEY=VALUE ... }
//
// For example:
//
//	https://accounts.google.com/ file=google-jwks.json ttl=24h
//
// Valid keys include:
//   - file: path to the JWKS file, relative to config file (required)
//   - ttl: duration to consider JWKS valid for issuer (optional)
//
// Blank lines and lines starting with # (ignoring leading whitespace)
// are ignored. Since fields are whitespace-delimited, values cannot contain
// any whitespace.
//
// The configuration file is treated as trustworthy and all file paths are
// accepted, including those pointing outside the directory containing the
// configuration file.
type LocalJwks struct {
	configFile string
	defaultTTL time.Duration
	clock      func() time.Time
}

func NewLocalJwks(configFile string, defaultTTL time.Duration) *LocalJwks {
	return NewLocalJwksWithClock(configFile, defaultTTL, time.Now)
}

func NewLocalJwksWithClock(configFile string, defaultTTL time.Duration, clock func() time.Time) *LocalJwks {
	return &LocalJwks{
		configFile: configFile,
		defaultTTL: defaultTTL,
		clock:      clock,
	}
}

func (l *LocalJwks) parseConfigFile() (entries map[string]localJwksConfig, err error) {
	file, err := os.Open(l.configFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries = make(map[string]localJwksConfig)
	scanner := bufio.NewScanner(file)
	for lineNum := 1; scanner.Scan(); lineNum++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		issuer := fields[0]
		var jwksFile string
		var ttl time.Duration
		for _, field := range fields[1:] {
			key, value, valid := strings.Cut(field, "=")
			if !valid {
				return nil, fmt.Errorf("field is not in key=value format on line %d", lineNum)
			}
			switch key {
			case "file":
				jwksFile = value
			case "ttl":
				ttl, err = time.ParseDuration(value)
				if err != nil {
					return nil, fmt.Errorf("parsing ttl as duration on line %d: %w", lineNum, err)
				}
			default:
				return nil, fmt.Errorf("unknown or invalid field %q on line %d", key, lineNum)
			}
		}
		if jwksFile == "" {
			return nil, fmt.Errorf("no file specified for issuer %q on line %d", issuer, lineNum)
		}
		if _, exists := entries[issuer]; exists {
			return nil, fmt.Errorf("duplicate definition for issuer %q on line %d", issuer, lineNum)
		}
		entries[issuer] = localJwksConfig{
			Issuer: issuer,
			File:   jwksFile,
			TTL:    ttl,
		}
	}
	return entries, nil
}

func (l *LocalJwks) FetchJwksWithExpires(ctx context.Context, issuer string) ([]byte, time.Time, error) {
	entries, err := l.parseConfigFile()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parsing local JWKS config file: %w", err)
	}
	entry, exists := entries[issuer]
	if !exists {
		return nil, time.Time{}, nil
	}
	if entry.TTL == 0 {
		entry.TTL = l.defaultTTL
	}
	now := l.clock()
	expires := now.Add(entry.TTL)
	filePath := filepath.Join(filepath.Dir(l.configFile), entry.File)
	value, err := os.ReadFile(filePath)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("reading local JWKS file %q for issuer: %w", filePath, err)
	}
	return value, expires, nil
}
