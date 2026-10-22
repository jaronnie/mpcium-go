package configsecret

// RecoverBusiness verifies every node's proof before threshold reconstruction.
func RecoverBusiness(m Manifest, e Envelope, parts map[string]Partial, binding string) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if err := e.Validate(m); err != nil {
		return nil, err
	}
	return recoverBusiness(m, e, parts, binding)
}
