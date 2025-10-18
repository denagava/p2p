package common

import (
	"encoding/json"
	"net"
	"sync"
	"time"
)

const (
	MAX_HOLE_PUNCH_ATTEMPTS = 20
	HOLE_PUNCH_INTERVAL     = 200 * time.Millisecond
	CleanupAfter            = 10 * time.Minute
)

type DeviceInfo struct {
	NodeID     string    `json:"node_id"`
	UserName   string    `json:"user_name"`
	DeviceName string    `json:"device_name"`
	PublicIP   string    `json:"public_ip"`
	PublicPort int       `json:"public_port"`
	PublicKey  string    `json:"public_key"`
	NATType    string    `json:"nat_type"`
	LastSeen   time.Time `json:"last_seen"`
	IsOnline   bool      `json:"is_online"`
}

type DeviceInfoJSON struct {
	NodeID     string `json:"node_id"`
	UserName   string `json:"user_name"`
	DeviceName string `json:"device_name"`
	PublicIP   string `json:"public_ip"`
	PublicPort int    `json:"public_port"`
	PublicKey  string `json:"public_key"`
	NATType    string `json:"nat_type"`
	LastSeen   string `json:"last_seen"`
	IsOnline   bool   `json:"is_online"`
}

func (d *DeviceInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(&DeviceInfoJSON{
		NodeID:     d.NodeID,
		UserName:   d.UserName,
		DeviceName: d.DeviceName,
		PublicIP:   d.PublicIP,
		PublicPort: d.PublicPort,
		PublicKey:  d.PublicKey,
		NATType:    d.NATType,
		LastSeen:   d.LastSeen.Format(time.RFC3339),
		IsOnline:   d.IsOnline,
	})
}

func (d *DeviceInfo) UnmarshalJSON(data []byte) error {
	var temp DeviceInfoJSON
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	d.NodeID = temp.NodeID
	d.UserName = temp.UserName
	d.DeviceName = temp.DeviceName
	d.PublicIP = temp.PublicIP
	d.PublicPort = temp.PublicPort
	d.PublicKey = temp.PublicKey
	d.NATType = temp.NATType
	d.IsOnline = temp.IsOnline

	if temp.LastSeen != "" {
		if lastSeen, err := time.Parse(time.RFC3339, temp.LastSeen); err == nil {
			d.LastSeen = lastSeen
		}
	}

	return nil
}

type RelayMessage struct {
	Type       string `json:"type"`
	FromNodeID string `json:"from_node_id"`
	ToNodeID   string `json:"to_node_id"`
	Data       []byte `json:"data"`
	Timestamp  int64  `json:"timestamp"`
}

type RelayClient struct {
	Addr     *net.UDPAddr
	NodeID   string
	LastSeen time.Time
}

type SafeDeviceMap struct {
	Devices map[string]*DeviceInfo
	Mutex   sync.RWMutex
}

type SafeRelayClients struct {
	Clients map[string]*RelayClient
	Mutex   sync.RWMutex
}
