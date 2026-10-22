package configsecret

import (
	"errors"
	"io"
)

func readLimit(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxMessage+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMessage {
		clear(b)
		return nil, errors.New("config message too large")
	}
	return b, nil
}
