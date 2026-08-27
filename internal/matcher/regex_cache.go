package matcher

import (
	"regexp"
	"sync"
)

// lruEntry is a single entry in the LRU cache.
type lruEntry struct {
	key     string
	re      *regexp.Regexp
	prev    *lruEntry
	next    *lruEntry
}

// lruCache is a fixed-size LRU cache for compiled regexps.
type lruCache struct {
	mu       sync.Mutex
	capacity int
	items    map[string]*lruEntry
	head     *lruEntry // most recently used
	tail     *lruEntry // least recently used
}

// newLRUCache creates an LRU cache with the given capacity.
func newLRUCache(capacity int) *lruCache {
	return &lruCache{
		capacity: capacity,
		items:    make(map[string]*lruEntry, capacity),
	}
}

// get retrieves a cached entry, promoting it to MRU position.
func (c *lruCache) get(key string) (*regexp.Regexp, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[key]; ok {
		c.moveToFront(e)
		return e.re, true
	}
	return nil, false
}

// put inserts or updates an entry, evicting LRU if at capacity.
func (c *lruCache) put(key string, re *regexp.Regexp) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[key]; ok {
		e.re = re
		c.moveToFront(e)
		return
	}
	e := &lruEntry{key: key, re: re}
	c.items[key] = e
	c.moveToFront(e)
	if len(c.items) > c.capacity {
		c.evict()
	}
}

func (c *lruCache) moveToFront(e *lruEntry) {
	if c.head == e {
		return
	}
	// Unlink
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}
	// Link at front
	e.prev = nil
	e.next = c.head
	if c.head != nil {
		c.head.prev = e
	}
	c.head = e
	if c.tail == nil {
		c.tail = e
	}
}

func (c *lruCache) evict() {
	if c.tail == nil {
		return
	}
	delete(c.items, c.tail.key)
	if c.tail.prev != nil {
		c.tail.prev.next = nil
	} else {
		c.head = nil
	}
	c.tail = c.tail.prev
}

// regexLRU is the package-level LRU cache for compiled regexps.
// Capacity: 512 entries — large enough to cover all templates in a typical scan.
var regexLRU = newLRUCache(512)

// cachedCompile wraps regexp.Compile with LRU caching.
// Re-compiled regexps are cached; on cache miss, the new regexp is stored.
// On capacity overflow, the least-recently-used entry is evicted.
func cachedCompile(pattern string) (*regexp.Regexp, error) {
	if re, ok := regexLRU.get(pattern); ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	regexLRU.put(pattern, re)
	return re, nil
}
