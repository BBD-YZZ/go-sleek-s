package distributed

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// discoverPort 是 UDP 广播发现使用的端口。
	discoverPort = 19234
	// heartbeatInterval 是节点心跳间隔。
	heartbeatInterval = 2 * time.Second
	// nodeTimeout 是节点无心跳视为离线的超时时间。
	nodeTimeout = 15 * time.Second
	// discoverBroadcastAddr 是广播地址。
	discoverBroadcastAddr = "255.255.255.255"
)

// DiscoverNodes 通过 UDP 广播发现同一 LAN 内的节点。
// timeout 控制发现的超时时间。
// 返回发现的节点列表。
func DiscoverNodes(timeout time.Duration) ([]*NodeInfo, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", discoverPort))
	if err != nil {
		return nil, fmt.Errorf("discover: resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("discover: listen udp: %w", err)
	}
	defer conn.Close()

	// 发送广播发现请求
	broadcastAddr, _ := net.ResolveUDPAddr("udp",
		fmt.Sprintf("%s:%d", discoverBroadcastAddr, discoverPort))
	request := []byte("GS-DISCOVER")
	if _, err := conn.WriteToUDP(request, broadcastAddr); err != nil {
		return nil, fmt.Errorf("discover: send broadcast: %w", err)
	}

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(timeout))

	var nodes []*NodeInfo
	buf := make([]byte, 4096)

	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			// 超时或关闭即退出
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			continue
		}

		resp := string(buf[:n])
		// 响应格式: "GS-NODE|<id>|<address>|<role>|<status>|<concurrency>"
		if !strings.HasPrefix(resp, "GS-NODE|") {
			continue
		}
		parts := strings.SplitN(resp, "|", 6)
		if len(parts) < 6 {
			continue
		}

		var role NodeRole
		switch parts[3] {
		case "master":
			role = NodeRoleMaster
		case "worker":
			role = NodeRoleWorker
		default:
			role = NodeRoleWorker
		}

		nodes = append(nodes, &NodeInfo{
			ID:          parts[1],
			Address:     parts[2],
			Role:        role,
			Status:      parts[4],
			Concurrency: parseInt(parts[5], 0),
			LastSeen:    time.Now(),
		})
	}

	return nodes, nil
}

// AddNode 手动添加一个已知地址的节点。
// 用于手动配置节点（当自动发现不可用时）。
func AddNode(address string) error {
	if address == "" {
		return fmt.Errorf("add-node: address is empty")
	}
	// 简单校验地址格式
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		// 可能只有 host，尝试补端口
		address = address + ":" + fmt.Sprint(discoverPort)
	}
	// 发送探测包
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return fmt.Errorf("add-node: resolve %s: %w", address, err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("add-node: dial %s: %w", address, err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GS-PROBE")); err != nil {
		return fmt.Errorf("add-node: probe failed: %w", err)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// 心跳广播
// ─────────────────────────────────────────────────────────────────────────────

// StartHeartbeat 启动节点心跳广播，定期向广播地址发送节点信息。
// stopCh 用于停止广播。
func StartHeartbeat(node *NodeInfo, stopCh chan struct{}) {
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", discoverPort))
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	broadcastAddr, _ := net.ResolveUDPAddr("udp",
		fmt.Sprintf("%s:%d", discoverBroadcastAddr, discoverPort))

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			msg := fmt.Sprintf("GS-NODE|%s|%s|%s|%s|%d",
				node.ID, node.Address, roleName(node.Role), node.Status, node.Concurrency)
			if _, err := conn.WriteToUDP([]byte(msg), broadcastAddr); err != nil {
				// 静默失败，下次重试
			}
		}
	}
}

// roleName 返回节点角色的英文标识。
func roleName(role NodeRole) string {
	switch role {
	case NodeRoleMaster:
		return "master"
	default:
		return "worker"
	}
}

// parseInt 安全解析整数，失败时返回 defaultValue。
func parseInt(s string, defaultValue int) int {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return defaultValue
	}
	return n
}

// NodePool 是节点集合，提供线程安全的增删查操作。
type NodePool struct {
	nodes map[string]*NodeInfo
	mu    sync.RWMutex
}

// NewNodePool 创建一个空的节点池。
func NewNodePool() *NodePool {
	return &NodePool{
		nodes: make(map[string]*NodeInfo),
	}
}

// Add 添加或更新一个节点。
func (p *NodePool) Add(node *NodeInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// 保留已有节点的其他字段
	if existing, ok := p.nodes[node.ID]; ok {
		node.CompletedJobs = existing.CompletedJobs
		node.MatchedJobs = existing.MatchedJobs
	}
	node.LastSeen = time.Now()
	p.nodes[node.ID] = node
}

// Remove 移除一个节点。
func (p *NodePool) Remove(nodeID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.nodes, nodeID)
}

// Get 获取指定 ID 的节点。
func (p *NodePool) Get(nodeID string) (*NodeInfo, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	node, ok := p.nodes[nodeID]
	return node, ok
}

// GetAll 返回所有节点的副本。
func (p *NodePool) GetAll() []*NodeInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]*NodeInfo, 0, len(p.nodes))
	for _, node := range p.nodes {
		cp := *node
		result = append(result, &cp)
	}
	return result
}

// GetOnline 返回状态为 "online" 或 "busy" 的节点。
func (p *NodePool) GetOnline() []*NodeInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]*NodeInfo, 0)
	for _, node := range p.nodes {
		if node.Status == "online" || node.Status == "busy" {
			cp := *node
			result = append(result, &cp)
		}
	}
	return result
}

// ExpireStale 标记超过超时时间的节点为离线。
func (p *NodePool) ExpireStale() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, node := range p.nodes {
		if time.Since(node.LastSeen) > nodeTimeout {
			node.Status = "offline"
			p.nodes[id] = node
		}
	}
}
