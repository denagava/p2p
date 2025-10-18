package main

import (
	"encoding/json"
	"log"
	"net"
	"sync"
	"time"
)

const (
	UDPPort       = ":8444"
	BufferSize    = 2048
	ClientTimeout = 5 * time.Minute
)

type RelayClient struct {
	Addr     *net.UDPAddr
	NodeID   string
	LastSeen time.Time
}

type RelayMessage struct {
	Type       string `json:"type"`
	FromNodeID string `json:"from_node_id"`
	ToNodeID   string `json:"to_node_id"`
	Data       []byte `json:"data"`
	Timestamp  int64  `json:"timestamp"`
}

var (
	clients      = make(map[string]*RelayClient)
	clientsMutex sync.RWMutex
	conn         *net.UDPConn
)

//var devices = common.SafeDeviceMap{Devices: make(map[string]*common.DeviceInfo)}// говно 

func main() {
	var err error
	addr, err := net.ResolveUDPAddr("udp", UDPPort)
	if err != nil {
		log.Fatal(err)
	}
	conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	go cleanupClients()

	log.Println("Relay server listening on", UDPPort)
	buf := make([]byte, BufferSize)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Println("Read error:", err)
			continue
		}
		go handleMessage(buf[:n], clientAddr)
	}
}

func handleMessage(data []byte, clientAddr *net.UDPAddr) {
	var msg RelayMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("Unmarshal error: %v", err)
		return
	}

	if time.Now().Unix()-msg.Timestamp > 30 {
		log.Printf("Old message ignored (timestamp: %d)", msg.Timestamp)
		return
	}

	clientsMutex.Lock()
	defer clientsMutex.Unlock()

	switch msg.Type {
	case "register":
		clients[msg.FromNodeID] = &RelayClient{
			Addr:     clientAddr,
			NodeID:   msg.FromNodeID,
			LastSeen: time.Now(),
		}
		log.Printf("Registered client: %s from %s", msg.FromNodeID, clientAddr)

	case "relay":
		if c, ok := clients[msg.FromNodeID]; ok {
			c.LastSeen = time.Now()
		}

		if target, ok := clients[msg.ToNodeID]; ok {
			log.Printf("Relaying message from %s to %s", msg.FromNodeID, msg.ToNodeID)

			_, err := conn.WriteToUDP(data, target.Addr)
			if err != nil {
				log.Printf("Relay send error: %v", err)
			} else {
				log.Printf("Relay successful to %s", target.Addr)
			}
		} else {
			log.Printf("Target client not found: %s", msg.ToNodeID)
			log.Printf("Known clients: %v", getClientIDs())
		}

	case "ping":
		if c, ok := clients[msg.FromNodeID]; ok {
			c.LastSeen = time.Now()
			log.Printf("Ping from %s", msg.FromNodeID)
		} else {
			clients[msg.FromNodeID] = &RelayClient{
				Addr:     clientAddr,
				NodeID:   msg.FromNodeID,
				LastSeen: time.Now(),
			}
			log.Printf("Auto-registered client from ping: %s", msg.FromNodeID)
		}
	}
}

func getClientIDs() []string {
	var ids []string
	for id := range clients {
		ids = append(ids, id)
	}
	return ids
}

func cleanupClients() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		clientsMutex.Lock()
		for id, c := range clients {
			if time.Since(c.LastSeen) > ClientTimeout {
				delete(clients, id)
				log.Println("Removed relay client", id)
			}
		}
		clientsMutex.Unlock()
	}
}
