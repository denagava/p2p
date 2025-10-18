package main

import (
	"crypto/subtle"
	"encoding/json"
	"familychat/common"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	ServerPort   = ":8443"
	ApiToken     = "family_secret_2024_token_change_me"
	MaxClients   = 30
	CleanupAfter = 10 * time.Minute
)

var devices = common.SafeDeviceMap{
	Devices: make(map[string]*common.DeviceInfo),
}

var startTime = time.Now()

func auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+ApiToken)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Обработчик регистрации устройства
func registerHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received registration request from: %s", r.RemoteAddr)

	var req struct {
		Token      string            `json:"token"`
		DeviceInfo common.DeviceInfo `json:"device_info"`
	}

	body, _ := io.ReadAll(r.Body)
	log.Printf("Request body: %s", string(body)) //важно для отладки

	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("JSON decode error: %v", err)
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// КРИТИЧЕСКАЯ ПРОВЕРКА
	if req.DeviceInfo.NodeID == "" {
		log.Printf("ERROR: Empty NodeID received! Full request: %+v", req)
		http.Error(w, `{"error":"NodeID is required"}`, http.StatusBadRequest)
		return
	}

	if subtle.ConstantTimeCompare([]byte(req.Token), []byte(ApiToken)) != 1 {
		http.Error(w, `{"error":"Unauthorized token"}`, http.StatusUnauthorized)
		return
	}

	devices.Mutex.Lock()
	defer devices.Mutex.Unlock()

	if len(devices.Devices) >= MaxClients {
		http.Error(w, `{"error":"Max clients reached"}`, http.StatusTooManyRequests)
		return
	}

	info := &common.DeviceInfo{
		NodeID:     req.DeviceInfo.NodeID,
		UserName:   req.DeviceInfo.UserName,
		DeviceName: req.DeviceInfo.DeviceName,
		PublicIP:   req.DeviceInfo.PublicIP,
		PublicPort: req.DeviceInfo.PublicPort,
		PublicKey:  req.DeviceInfo.PublicKey,
		NATType:    req.DeviceInfo.NATType,
		LastSeen:   time.Now(),
		IsOnline:   true,
	}

	devices.Devices[req.DeviceInfo.NodeID] = info // Ключ = NodeID

	log.Printf("SUCCESS: Registered device - NodeID: '%s', IP: %s, Port: %d, Total: %d",
		info.NodeID, info.PublicIP, info.PublicPort, len(devices.Devices))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "registered",
		"node_id":     info.NodeID,
		"server_time": time.Now().Unix(),
		"total_peers": len(devices.Devices) - 1,
	})
}

type ClientDeviceInfo struct {
	NodeID     string `json:"node_id"`
	UserName   string `json:"user_name"`
	DeviceName string `json:"device_name"`
	PublicIP   string `json:"public_ip"`
	PublicPort int    `json:"public_port"`
	PublicKey  string `json:"public_key"`
	NATType    string `json:"nat_type"`
}

func peersHandler(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")

	devices.Mutex.Lock()
	if d, ok := devices.Devices[nodeID]; ok {
		d.LastSeen = time.Now()
		d.IsOnline = true
	}
	devices.Mutex.Unlock()

	devices.Mutex.RLock()
	defer devices.Mutex.RUnlock()

	var list []common.DeviceInfo
	for id, d := range devices.Devices {
		if id == nodeID {
			continue
		}
		if d.NodeID != "" && d.PublicIP != "" {
			list = append(list, *d)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(struct {
		Status string              `json:"status"`
		Peers  []common.DeviceInfo `json:"peers"`
		Count  int                 `json:"count"`
	}{
		Status: "success",
		Peers:  list,
		Count:  len(list),
	})
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	devices.Mutex.RLock()
	defer devices.Mutex.RUnlock()

	online := 0
	for _, d := range devices.Devices {
		if d.IsOnline && time.Since(d.LastSeen) < CleanupAfter {
			online++
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "running",
		"uptime":        time.Since(startTime).String(),
		"total":         len(devices.Devices),
		"online":        online,
		"max_clients":   MaxClients,
		"cleanup_after": CleanupAfter.Seconds(),
	})
}

func cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		devices.Mutex.Lock()
		log.Printf("Cleanup: checking %d devices", len(devices.Devices))
		for id, d := range devices.Devices {
			if time.Since(d.LastSeen) > 5*time.Minute {
				log.Printf("Cleanup: removing device %s (last seen: %v)", id, d.LastSeen)
				delete(devices.Devices, id)
			}
		}
		log.Printf("Cleanup: %d devices remaining", len(devices.Devices))
		devices.Mutex.Unlock()
	}
}

func main() {
	go cleanupLoop()

	mux := http.NewServeMux()

	mux.Handle("/register", cors(http.HandlerFunc(registerHandler)))
	mux.Handle("/peers", cors(http.HandlerFunc(peersHandler)))
	mux.Handle("/status", cors(http.HandlerFunc(statusHandler)))

	mux.Handle("/debug", cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		devices.Mutex.RLock()
		defer devices.Mutex.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_devices": len(devices.Devices),
			"devices":       devices.Devices,
		})
	})))

	log.Printf("Signaling server listening on %s", ServerPort)
	log.Fatal(http.ListenAndServeTLS(ServerPort, "cert.pem", "key.pem", mux))
}
