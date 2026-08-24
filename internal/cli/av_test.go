package cli

import (
	"errors"
	"sync"

	"github.com/steipete/ordercli/internal/config"
)

func init() {
	store := struct {
		sync.Mutex
		values map[string][]byte
	}{values: make(map[string][]byte)}
	config.SetAVCredentialForTests(func(path string, action string, input []byte) ([]byte, error) {
		store.Lock()
		defer store.Unlock()
		switch action {
		case "get":
			value, ok := store.values[path]
			if !ok {
				return nil, errors.New("missing test ordercli credential")
			}
			return append([]byte(nil), value...), nil
		case "store":
			store.values[path] = append([]byte(nil), input...)
			return nil, nil
		case "forget":
			delete(store.values, path)
			return nil, nil
		default:
			return nil, errors.New("unsupported test ordercli credential action")
		}
	})
}
