package mpcium

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"regexp"
)

var sdkNodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func cloneSDKNodes(nodes map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	result := map[string]ed25519.PublicKey{}
	for id, key := range nodes {
		result[id] = bytes.Clone(key)
	}
	return result
}
func validateSDKNodes(nodes map[string]ed25519.PublicKey) error {
	if len(nodes) < 2 || len(nodes) > 8 {
		return errors.New("SDK credentials require 2–8 trusted nodes; export a new credentials bundle")
	}
	seen := map[string]bool{}
	for id, key := range nodes {
		if !sdkNodeIDPattern.MatchString(id) || len(key) != ed25519.PublicKeySize || seen[string(key)] {
			return errors.New("invalid or duplicate SDK node identity")
		}
		seen[string(key)] = true
	}
	return nil
}
