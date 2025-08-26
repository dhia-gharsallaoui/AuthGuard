package concurrency

import (
	"sync"
)

type MutexManager struct {
	mutexes map[string]*sync.Mutex
	mapMu   sync.RWMutex
}

func NewMutexManager() *MutexManager {
	return &MutexManager{
		mutexes: make(map[string]*sync.Mutex),
	}
}

func (m *MutexManager) Lock(key string) {
	m.mapMu.RLock()
	mu, exists := m.mutexes[key]
	m.mapMu.RUnlock()

	if !exists {
		m.mapMu.Lock()
		mu, exists = m.mutexes[key]
		if !exists {
			mu = &sync.Mutex{}
			m.mutexes[key] = mu
		}
		m.mapMu.Unlock()
	}

	mu.Lock()
}

func (m *MutexManager) Unlock(key string) {
	m.mapMu.RLock()
	mu, exists := m.mutexes[key]
	m.mapMu.RUnlock()

	if exists {
		mu.Unlock()
	}
}
