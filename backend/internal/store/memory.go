package store

import (
	"sync"
	"time"

	"sharaga/internal/models"
)

type entry struct {
	analysis *models.Analysis
	packets  []models.PacketRow
	expires  time.Time
}

type Memory struct {
	mu   sync.RWMutex
	ttl  time.Duration
	data map[string]*entry
}

func New(ttl time.Duration) *Memory {
	m := &Memory{
		ttl:  ttl,
		data: make(map[string]*entry),
	}
	go m.gcLoop()
	return m
}

func (m *Memory) Put(a *models.Analysis, packets []models.PacketRow) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[a.ID] = &entry{
		analysis: a,
		packets:  packets,
		expires:  time.Now().Add(m.ttl),
	}
}

func (m *Memory) Get(id string) (*models.Analysis, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.data[id]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.analysis, true
}

func (m *Memory) GetWithPackets(id string) (*models.Analysis, []models.PacketRow, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.data[id]
	if !ok || time.Now().After(e.expires) {
		return nil, nil, false
	}
	return e.analysis, e.packets, true
}

func (m *Memory) gcLoop() {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for range t.C {
		m.mu.Lock()
		now := time.Now()
		for id, e := range m.data {
			if now.After(e.expires) {
				delete(m.data, id)
			}
		}
		m.mu.Unlock()
	}
}
