package core

import (
	"fmt"
	"sync"

	"vless-core/protocol"
)

// Validator implements protocol.Validator with a concurrent UUID -> user map.
// It mirrors Xray-core's vless.MemoryValidator, including the UUID byte
// normalization used for looking up users.
type Validator struct {
	mu    sync.RWMutex
	users map[protocol.UUID]string
}

func NewValidator(users []UserConfig) (*Validator, error) {
	v := &Validator{users: make(map[protocol.UUID]string, len(users))}
	for _, u := range users {
		id, err := protocol.ParseUUID(u.ID)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", u.Email, err)
		}
		key := protocol.NormalizeUUID(id)
		if _, exists := v.users[key]; exists {
			return nil, fmt.Errorf("duplicate user id %s", id.String())
		}
		v.users[key] = u.Email
	}
	return v, nil
}

// Get returns the user's email for a wire UUID.
func (v *Validator) Get(id protocol.UUID) (string, bool) {
	v.mu.RLock()
	email, ok := v.users[protocol.NormalizeUUID(id)]
	v.mu.RUnlock()
	return email, ok
}

func (v *Validator) Count() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.users)
}
