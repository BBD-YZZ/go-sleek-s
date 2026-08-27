package plugin

import "sync"

var (
	registry = make(map[string]Plugin)
	mu       sync.RWMutex
)

// Register 注册插件，通常在插件包的 init() 中调用。
func Register(p Plugin) {
	mu.Lock()
	defer mu.Unlock()
	id := p.Meta().ID
	if _, exists := registry[id]; exists {
		panic("plugin already registered: " + id)
	}
	registry[id] = p
}

// Get 按 ID 获取插件。
func Get(id string) (Plugin, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[id]
	return p, ok
}

// All 返回所有已注册插件。
func All() []Plugin {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Plugin, 0, len(registry))
	for _, p := range registry {
		result = append(result, p)
	}
	return result
}

// IDs 返回所有插件 ID。
func IDs() []string {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]string, 0, len(registry))
	for id := range registry {
		result = append(result, id)
	}
	return result
}

// Count 返回已注册插件数量。
func Count() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(registry)
}
