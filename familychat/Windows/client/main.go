package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"familychat/common"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type RegisterRequest struct {
	Token      string            `json:"token"`
	DeviceInfo common.DeviceInfo `json:"device_info"`
}

type MessageData struct {
	ID     string `json:"id"`
	Text   string `json:"text"`
	Time   int64  `json:"time"`
	NodeID string `json:"node_id"`
}

type PeersResponse struct {
	Status string              `json:"status"`
	Peers  []common.DeviceInfo `json:"peers"`
	Count  int                 `json:"count"`
}

type RelayMessage struct {
	Type       string `json:"type"`
	FromNodeID string `json:"from_node_id"`
	ToNodeID   string `json:"to_node_id"`
	Data       []byte `json:"data"`
	Timestamp  int64  `json:"timestamp"`
}

const (
	SignalURL       = "https://10.147.17.230:8443"
	RelayUDP        = "10.147.17.230:8444"
	ApiToken        = "family_secret_2024_token_change_me"
	MaxHoleAttempts = 20
	HoleInterval    = 200 * time.Millisecond
	PeerFetchInt    = 30 * time.Second
)

var (
	curve         = ecdh.P256()
	privKey       *ecdh.PrivateKey
	pubKey        []byte
	nodeID        string
	connUDP       *net.UDPConn
	peers         = map[string]common.DeviceInfo{}
	messageBox    *widget.Entry
	peerList      *widget.List
	statusBar     *widget.Label
	mainWindow    fyne.Window
	peerListMutex sync.RWMutex
	messageScroll *container.Scroll
)

var (
	receivedMessages      = make(map[string]int64)
	receivedMessagesMutex sync.RWMutex
	messageTimeout        = 2 * time.Minute
)

func loadOrCreateNodeID() (string, *ecdh.PrivateKey, error) {
	data, err := os.ReadFile("device_private_key.txt")
	if err == nil && len(data) > 0 {
		privKey, err := curve.NewPrivateKey(data)
		if err == nil {
			pubKey = privKey.PublicKey().Bytes()
			nodeID = hex.EncodeToString(pubKey)[:16]
			log.Printf("Loaded existing device ID: %s", nodeID)
			return nodeID, privKey, nil
		}
		log.Printf("Failed to load private key, generating new one: %v", err)
	}

	log.Println("Generating new device keys...")
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}

	// Сохраняем приватный ключ в файл
	privKeyBytes := privKey.Bytes()
	if err := os.WriteFile("device_private_key.txt", privKeyBytes, 0600); err != nil {
		log.Printf("Failed to save private key: %v", err)
	} else {
		log.Printf("Saved device private key to device_private_key.txt")
	}

	pubKey = privKey.PublicKey().Bytes()
	nodeID = hex.EncodeToString(pubKey)[:16]
	log.Printf("New device ID generated: %s", nodeID)
	return nodeID, privKey, nil
}

func initKeys() {
	var err error
	nodeID, privKey, err = loadOrCreateNodeID()
	if err != nil {
		log.Fatal(err)
	}
}

func getBestIP() string {
	log.Println("Scanning network interfaces for correct ZeroTier IP...")

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Error getting interfaces: %v", err)
		return "127.0.0.1"
	}

	for _, iface := range interfaces {
		if strings.Contains(iface.Name, "ZeroTier") ||
			strings.HasPrefix(iface.Name, "zt") ||
			strings.Contains(iface.Name, "45b6e887e25430c7") {

			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
					discoveredIP := ipNet.IP.String()
					log.Printf("Found ZeroTier interface: %s, IP: %s", iface.Name, discoveredIP)

					return discoveredIP
				}
			}
		}
	}

	log.Printf("ZeroTier interface not found, using fallback IP detection")

	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		conn.Close()
		fallbackIP := localAddr.IP.String()
		log.Printf("Using fallback IP: %s", fallbackIP)
		return fallbackIP
	}

	return "127.0.0.1"
}

func registerSelf() {
	laddr := connUDP.LocalAddr().(*net.UDPAddr)

	publicIP := getBestIP()
	log.Printf("Auto-detected IP for registration: %s", publicIP)

	info := common.DeviceInfo{
		NodeID:     nodeID,
		UserName:   "FamilyUser",
		DeviceName: "Device1",
		PublicIP:   publicIP,
		PublicPort: laddr.Port,
		PublicKey:  hex.EncodeToString(pubKey),
		NATType:    "ZeroTier",
	}

	log.Printf("CLIENT DEBUG: NodeID='%s', PublicKey='%s'", nodeID, hex.EncodeToString(pubKey))
	log.Printf("CLIENT DEBUG: DeviceInfo: %+v", info)

	req := RegisterRequest{Token: ApiToken, DeviceInfo: info}
	data, err := json.Marshal(req)
	if err != nil {
		log.Printf("JSON marshal error: %v", err)
		return
	}

	log.Printf("CLIENT DEBUG: Sending JSON: %s", string(data))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	httpReq, err := http.NewRequest("POST", SignalURL+"/register", bytes.NewReader(data))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		fyne.Do(func() {
			statusBar.SetText("Status: Failed to create request")
		})
		return
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+ApiToken)

	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("Registration error: %v", err)
		fyne.Do(func() {
			statusBar.SetText("Status: Registration failed - " + err.Error())
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Registration failed with status: %s, response: %s", resp.Status, string(body))
		fyne.Do(func() {
			statusBar.SetText("Status: Registration failed - " + resp.Status)
		})
		return
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Failed to parse registration response: %v", err)
		fyne.Do(func() {
			statusBar.SetText("Status: Registration response parse error")
		})
		return
	}

	log.Printf("Registration successful: %v", result)
	fyne.Do(func() {
		statusBar.SetText("Status: Registered successfully")
	})
}

func registerWithRelay() {
	msg := map[string]interface{}{
		"type":         "register",
		"from_node_id": nodeID,
		"timestamp":    time.Now().Unix(),
	}
	b, _ := json.Marshal(msg)
	relayAddr, _ := net.ResolveUDPAddr("udp", RelayUDP)
	connUDP.WriteToUDP(b, relayAddr)
	log.Printf("Registered with relay server: %s", nodeID)
}

func sendRelayPing() {
	msg := map[string]interface{}{
		"type":         "ping",
		"from_node_id": nodeID,
		"timestamp":    time.Now().Unix(),
	}
	b, _ := json.Marshal(msg)
	relayAddr, _ := net.ResolveUDPAddr("udp", RelayUDP)
	connUDP.WriteToUDP(b, relayAddr)
}

func fetchPeers() {
	url := fmt.Sprintf("%s/peers?node_id=%s", SignalURL, nodeID)
	log.Printf("Fetching peers from: %s", url)

	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 10 * time.Second,
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		updateStatus("Failed to create peers request")
		return
	}
	req.Header.Set("Authorization", "Bearer "+ApiToken)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Fetch peers error: %v", err)
		updateStatus("Failed to fetch peers - " + err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Fetch peers failed with status: %s, response: %s", resp.Status, string(body))
		updateStatus("Failed to fetch peers - " + resp.Status)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		updateStatus("Failed to read peers response")
		return
	}

	log.Printf("Raw peers response: %s", string(body))

	var pr PeersResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		log.Printf("Failed to parse peers response: %v", err)
		updateStatus("Failed to parse peers data")
		return
	}

	log.Printf("Parsed response - Status: %s, Count: %d", pr.Status, pr.Count)

	peerListMutex.Lock()
	peers = make(map[string]common.DeviceInfo)
	for _, d := range pr.Peers {
		if d.NodeID != "" && d.PublicKey != "" && d.NodeID != nodeID {
			peers[d.NodeID] = d
			log.Printf("Added peer: %s (%s)", d.DeviceName, d.NodeID)
		}
	}
	peerListMutex.Unlock()

	updateStatus(fmt.Sprintf("Status: %d peers available", len(peers)))
	refreshPeerList()
}

func holePunch(addr *net.UDPAddr) {
	for i := 0; i < MaxHoleAttempts; i++ {
		connUDP.WriteToUDP([]byte("HOLE"), addr)
		time.Sleep(HoleInterval)
	}
}

func sendRelay(toNodeID string, data []byte) {
	msg := map[string]interface{}{
		"type":         "relay",
		"from_node_id": nodeID,
		"to_node_id":   toNodeID,
		"data":         data,
		"timestamp":    time.Now().Unix(),
	}
	b, _ := json.Marshal(msg)
	relayAddr, _ := net.ResolveUDPAddr("udp", RelayUDP)
	connUDP.WriteToUDP(b, relayAddr)
}

func isDuplicateMessage(messageHash string) bool {
	receivedMessagesMutex.RLock()
	defer receivedMessagesMutex.RUnlock()

	if timestamp, exists := receivedMessages[messageHash]; exists {
		if time.Now().Unix()-timestamp < int64(messageTimeout.Seconds()) {
			return true
		}
	}
	return false
}

func markMessageAsReceived(messageHash string) {
	receivedMessagesMutex.Lock()
	defer receivedMessagesMutex.Unlock()

	receivedMessages[messageHash] = time.Now().Unix()

	go func() {
		time.Sleep(messageTimeout)
		receivedMessagesMutex.Lock()
		delete(receivedMessages, messageHash)
		receivedMessagesMutex.Unlock()
	}()
}

func createMessageHash(peerID string, ciphertext []byte) string {
	hash := sha256.New()
	hash.Write([]byte(peerID))
	hash.Write(ciphertext)
	return hex.EncodeToString(hash.Sum(nil))
}

func sendMessage(peer common.DeviceInfo, plaintext string) {
	log.Printf("Sending message to %s (NodeID: %s)", peer.DeviceName, peer.NodeID)

	if privKey == nil {
		log.Println("Cannot send: private key is nil")
		return
	}
	if peer.PublicKey == "" {
		log.Println("Cannot send: peer public key is empty")
		return
	}

	messageData := MessageData{
		ID:     fmt.Sprintf("%d-%s", time.Now().UnixNano(), nodeID),
		Text:   plaintext,
		Time:   time.Now().Unix(),
		NodeID: nodeID,
	}

	jsonData, err := json.Marshal(messageData)
	if err != nil {
		log.Printf("Failed to marshal message data: %v", err)
		return
	}

	pubBytes, err := hex.DecodeString(peer.PublicKey)
	if err != nil {
		log.Printf("Failed to decode peer public key: %v", err)
		return
	}

	peerPub, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		log.Printf("Failed to create peer public key: %v", err)
		return
	}

	shared, err := privKey.ECDH(peerPub)
	if err != nil {
		log.Printf("Failed to compute shared secret: %v", err)
		return
	}

	block, err := aes.NewCipher(shared)
	if err != nil {
		log.Printf("Failed to create AES cipher: %v", err)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("Failed to create GCM: %v", err)
		return
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Printf("Failed to generate nonce: %v", err)
		return
	}

	ciphertext := gcm.Seal(nonce, nonce, jsonData, nil)
	log.Printf("Encryption successful, message ID: %s", messageData.ID)

	if peer.PublicIP != "" && peer.PublicPort != 0 {
		addr := &net.UDPAddr{IP: net.ParseIP(peer.PublicIP), Port: peer.PublicPort}
		log.Printf("Attempting direct connection to %s", addr)

		for i := 0; i < 5; i++ {
			connUDP.WriteToUDP([]byte("HOLE"), addr)
			time.Sleep(100 * time.Millisecond)
		}

		_, err := connUDP.WriteToUDP(ciphertext, addr)
		if err != nil {
			log.Printf("❌ Direct send failed: %v", err)
		} else {
			log.Printf("✅ Direct send succeeded to %s", addr)
		}
	}

	log.Printf("Attempting relay send via %s", RelayUDP)
	sendRelay(peer.NodeID, ciphertext)

	displayMessage(fmt.Sprintf("You to %s: %s", peer.DeviceName, plaintext))
	log.Printf("Message sent to %s", peer.DeviceName)
}

func testZeroTierConnectivity() {
	log.Println("Testing ZeroTier connectivity...")

	addrs, err := net.LookupHost("10.147.17.230")
	if err != nil {
		log.Printf("DNS resolution failed: %v", err)
	} else {
		log.Printf("DNS resolution: %v", addrs)
	}

	conn, err := net.DialTimeout("tcp", "10.147.17.230:8443", 5*time.Second)
	if err != nil {
		log.Printf("TCP connection to signaling server failed: %v", err)
	} else {
		conn.Close()
		log.Printf("TCP connection to signaling server: OK")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "10.147.17.230:8444")
	if err != nil {
		log.Printf("UDP address resolution failed: %v", err)
	} else {
		testConn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			log.Printf("UDP connection failed: %v", err)
		} else {
			testConn.Close()
			log.Printf("UDP connection: OK")
		}
	}

	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			log.Printf("Interface %s: %s", iface.Name, addr)
		}
	}
}

func debugNetworkInterfaces() {
	log.Println("Detailed network interface scan:")

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Error getting interfaces: %v", err)
		return
	}

	for _, iface := range interfaces {
		log.Printf("Interface: %s (MTU: %d, Flags: %v)", iface.Name, iface.MTU, iface.Flags)

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok {
				log.Printf("Address: %s (IPv4: %v, Loopback: %v)",
					ipNet.String(),
					ipNet.IP.To4() != nil,
					ipNet.IP.IsLoopback())
			}
		}
	}
}

func startNetworking() {
	laddr, _ := net.ResolveUDPAddr("udp", ":0")
	var err error
	connUDP, err = net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
		return
	}

	debugNetworkInterfaces()
	go testZeroTierConnectivity()

	go testZeroTierConnectivity()

	fyne.Do(func() {
		statusBar.SetText("Status: Starting registration...")
	})

	registerSelf()
	registerWithRelay()

	registerSelf()
	registerWithRelay()

	go func() {
		ticker := time.NewTicker(PeerFetchInt)
		for range ticker.C {
			fetchPeers()
			sendRelayPing()
		}
	}()

	go handleIncomingMessages()
}

func handleIncomingMessages() {
	log.Println("UDP message listener started successfully")
	buf := make([]byte, 4096)

	for {
		n, addr, err := connUDP.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading from UDP: %v", err)
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		log.Printf("Received %d bytes from %s", n, addr)

		if string(data) == "HOLE" {
			log.Printf("Hole punch received from %s", addr)
			continue
		}

		messageHash := createMessageHash(addr.String(), data)

		if isDuplicateMessage(messageHash) {
			log.Printf("Skipping duplicate message from %s", addr)
			continue
		}

		markMessageAsReceived(messageHash)

		var relayMsg RelayMessage
		if err := json.Unmarshal(data, &relayMsg); err == nil && relayMsg.Type == "relay" {
			log.Printf("Relay message from %s to %s", relayMsg.FromNodeID, relayMsg.ToNodeID)

			if relayMsg.ToNodeID == nodeID {
				relayHash := createMessageHash(relayMsg.FromNodeID, relayMsg.Data)
				if isDuplicateMessage(relayHash) {
					log.Printf("Skipping duplicate relay message from %s", relayMsg.FromNodeID)
					continue
				}
				markMessageAsReceived(relayHash)

				log.Printf("Attempting to decrypt relay message...")
				if plaintext, peerName, msgID, ok := tryDecryptMessage(relayMsg.Data); ok {
					log.Printf("Decrypted relay message from %s: '%s' (ID: %s)", peerName, plaintext, msgID)
					displayMessage(fmt.Sprintf("[Relay] %s: %s", peerName, plaintext))
				} else {
					log.Printf("Relay decryption failed")
				}
				continue
			}

			log.Printf("Attempting to decrypt as direct message...")
			if plaintext, peerName, msgID, ok := tryDecryptMessage(data); ok {
				log.Printf("Decrypted direct message from %s: '%s' (ID: %s)", peerName, plaintext, msgID)
				displayMessage(fmt.Sprintf("%s: %s", peerName, plaintext))
				continue
			}

			log.Printf("Unknown message format from %s", addr)
		}
	}
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func displayMessage(text string) {
	fyne.Do(func() {
		timestamp := time.Now().Format("15:04:05")
		formattedMessage := fmt.Sprintf("[%s] %s\n", timestamp, text)

		messageBox.SetText(messageBox.Text + formattedMessage)

		messageBox.CursorColumn = 0
		messageBox.CursorRow = len(messageBox.Text)

		if messageScroll != nil {
			messageScroll.ScrollToBottom()
		}
	})
}

func tryDecryptMessage(ciphertext []byte) (string, string, string, bool) {
	peerListMutex.RLock()
	defer peerListMutex.RUnlock()

	log.Printf("Trying to decrypt message with %d peers", len(peers))

	if len(peers) == 0 {
		log.Printf("No peers available for decryption")
		return "", "", "", false
	}

	for nodeID, peer := range peers {
		log.Printf("Trying peer: %s (%s)", peer.DeviceName, nodeID)

		if peer.PublicKey == "" {
			log.Printf("Peer %s has empty public key", peer.DeviceName)
			continue
		}

		pubBytes, err := hex.DecodeString(peer.PublicKey)
		if err != nil {
			log.Printf("Failed to decode public key for %s: %v", peer.DeviceName, err)
			continue
		}

		peerPub, err := curve.NewPublicKey(pubBytes)
		if err != nil {
			log.Printf("Failed to create public key for %s: %v", peer.DeviceName, err)
			continue
		}

		shared, err := privKey.ECDH(peerPub)
		if err != nil {
			log.Printf("Failed to compute shared secret for %s: %v", peer.DeviceName, err)
			continue
		}

		block, err := aes.NewCipher(shared)
		if err != nil {
			log.Printf("Failed to create AES cipher for %s: %v", peer.DeviceName, err)
			continue
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			log.Printf("Failed to create GCM for %s: %v", peer.DeviceName, err)
			continue
		}

		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			log.Printf("Ciphertext too short for %s: %d < %d", peer.DeviceName, len(ciphertext), nonceSize)
			continue
		}

		nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err == nil {
			var msgData MessageData
			if err := json.Unmarshal(plaintext, &msgData); err != nil {
				log.Printf("Failed to parse message data: %v", err)
				return string(plaintext), peer.DeviceName, "", true
			}

			log.Printf("Successfully decrypted message from %s, ID: %s", peer.DeviceName, msgData.ID)

			messageHash := createMessageHash(msgData.NodeID, []byte(msgData.ID))
			if isDuplicateMessage(messageHash) {
				log.Printf("Skipping duplicate message from %s, ID: %s", peer.DeviceName, msgData.ID)
				return "", "", "", false
			}
			markMessageAsReceived(messageHash)

			return msgData.Text, peer.DeviceName, msgData.ID, true
		} else {
			log.Printf("Decryption failed for %s: %v", peer.DeviceName, err)
		}
	}

	log.Printf("Failed to decrypt message with any peer")
	return "", "", "", false
}

func updateStatus(text string) {
	fyne.Do(func() {
		statusBar.SetText(text)
	})
}

func refreshPeerList() {
	fyne.Do(func() {
		peerList.Refresh()
	})
}

func main() {
	initKeys()

	a := app.New()
	mainWindow = a.NewWindow("Family Chat")
	mainWindow.Resize(fyne.NewSize(800, 600))

	statusBar = widget.NewLabel("Status: Initializing...")

	peerList = widget.NewList(
		func() int {
			return len(peers)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			keys := make([]string, 0, len(peers))
			for k := range peers {
				keys = append(keys, k)
			}
			if i < len(keys) {
				peer := peers[keys[i]]
				o.(*widget.Label).SetText(fmt.Sprintf("%s (%s)", peer.DeviceName, peer.UserName))
			}
		},
	)

	peerList.OnSelected = func(id widget.ListItemID) {
		keys := make([]string, 0, len(peers))
		for k := range peers {
			keys = append(keys, k)
		}
		if id < len(keys) {
			peer := peers[keys[id]]
			fyne.Do(func() {
				statusBar.SetText(fmt.Sprintf("Selected: %s - %s:%d", peer.DeviceName, peer.PublicIP, peer.PublicPort))
			})
		}
	}

	messageBox = widget.NewMultiLineEntry()
	messageBox.Wrapping = fyne.TextWrapWord
	messageBox.Disable()
	messageBox.SetPlaceHolder("Messages will appear here...")

	input := widget.NewEntry()
	input.SetPlaceHolder("Type your message here...")
	input.OnSubmitted = func(text string) {
		if text != "" {
			for _, p := range peers {
				go sendMessage(p, text)
			}
			input.SetText("")
		}
	}

	sendBtn := widget.NewButtonWithIcon("Send", theme.MailSendIcon(), func() {
		text := input.Text
		if text != "" {
			for _, p := range peers {
				go sendMessage(p, text)
			}
			input.SetText("")
		}
	})

	refreshBtn := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), func() {
		fyne.Do(func() {
			statusBar.SetText("Status: Refreshing peers...")
		})
		go fetchPeers()
	})

	debugBtn := widget.NewButtonWithIcon("Debug", theme.DocumentIcon(), func() {
		peerListMutex.RLock()
		defer peerListMutex.RUnlock()

		info := fmt.Sprintf("My NodeID: %s\n", nodeID)
		info += fmt.Sprintf("Peers count: %d\n", len(peers))
		for _, p := range peers {
			keySnippet := p.PublicKey
			if len(p.PublicKey) > 20 {
				keySnippet = p.PublicKey[:20] + "..."
			}
			info += fmt.Sprintf("Peer: %s, Key: %s\n", p.DeviceName, keySnippet)
		}

		modalContent := widget.NewLabel(info)
		scrollContainer := container.NewScroll(modalContent)
		scrollContainer.SetMinSize(fyne.NewSize(400, 300))

		widget.ShowModalPopUp(scrollContainer, mainWindow.Canvas())
	})

	testBtn := widget.NewButtonWithIcon("Test ZeroTier", theme.ComputerIcon(), func() {
		go testZeroTierConnectivity()
	})

	buttonContainer := container.NewHBox(
		refreshBtn,
		debugBtn,
		testBtn,
	)

	leftPanel := container.NewBorder(
		widget.NewLabelWithStyle("Connected Peers", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		buttonContainer,
		nil,
		nil,
		peerList,
	)

	messageScroll = container.NewScroll(messageBox)

	rightPanel := container.NewBorder(
		widget.NewLabelWithStyle("Messages", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		container.NewBorder(
			nil, nil, nil, sendBtn,
			input,
		),
		nil, nil,
		messageScroll,
	)

	split := container.NewHSplit(leftPanel, rightPanel)
	split.SetOffset(0.25)

	mainContent := container.NewBorder(
		nil,
		statusBar,
		nil, nil,
		split,
	)

	mainWindow.SetContent(mainContent)

	go startNetworking()

	mainWindow.ShowAndRun()
}
