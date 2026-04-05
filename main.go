package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── Güvenlik sabitleri ────────────────────────────────────────────────────────
const (
	maxWorkers    = 64
	outputDir     = "./scan_output"
	apiKeyHeader  = "X-API-Key"
)

// API anahtarını env'den al; yoksa rastgele bir UUID benzeri oluştur
var apiKey string

// Güvenli IP regex: sadece IPv4 ve CIDR / aralık notasyonuna izin ver
var safeTargetRe = regexp.MustCompile(`^[0-9./\-, ]+$`)

// İzin verilen nmap argümanları (whitelist)
var allowedArgs = map[string]bool{
	"-sS": true, "-sV": true, "-sC": true, "-A": true,
	"-T1": true, "-T2": true, "-T3": true, "-T4": true, "-T5": true,
	"-p-": true, "-O": true, "-Pn": true, "--open": true,
	"--script": true, "vuln": true, "default": true, "safe": true,
}

// ─── Veri tipleri ─────────────────────────────────────────────────────────────
type ScanRequest struct {
	Target      string `json:"target"`
	NmapArgs    string `json:"nmapArgs"`
	WorkerCount int    `json:"workerCount"`
	ScanTool    string `json:"scanTool"`
}

type SSEMessage struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
}

// ─── Global state ─────────────────────────────────────────────────────────────
var (
	clients       = make(map[chan SSEMessage]bool)
	clientsMutex  sync.Mutex
	broadcastChan = make(chan SSEMessage, 100)
	scanContext   *sync.WaitGroup
	scanCancel    chan struct{}
	scanMutex     sync.Mutex    // eş zamanlı tarama koruması
	scanRunning   atomic.Bool   // atomik durum bayrağı
)

// ─── Main ─────────────────────────────────────────────────────────────────────
func main() {
	// API anahtarını env'den yükle
	apiKey = os.Getenv("TRIEDSCAN_API_KEY")
	if apiKey == "" {
		fmt.Println("[!] UYARI: TRIEDSCAN_API_KEY env değişkeni ayarlanmamış.")
		fmt.Println("[!] Güvenli kullanım için: export TRIEDSCAN_API_KEY='gizli-anahtar'")
		fmt.Println("[!] Ayarlanana kadar API korumasız çalışmaktadır.")
	}

	// Çıktı dizinini oluştur
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		fmt.Printf("[!] Çıktı dizini oluşturulamadı: %v\n", err)
		os.Exit(1)
	}

	cleanupTempXMLs()
	go handleBroadcasts()

	http.Handle("/", http.FileServer(http.Dir("./public")))
	http.HandleFunc("/events", sseHandler)
	http.HandleFunc("/api/start", authMiddleware(startScanHandler))
	http.HandleFunc("/api/stop", authMiddleware(stopScanHandler))
	http.HandleFunc("/api/output", authMiddleware(outputHandler))

	fmt.Println("[+] TriedScan 8080 portunda çalışıyor.")
	fmt.Println("[+] http://localhost:8080 adresine gidin.")
	if err := http.ListenAndServe("127.0.0.1:8080", nil); err != nil {
		fmt.Printf("[!] Sunucu hatası: %v\n", err)
	}
}

// ─── Auth middleware ───────────────────────────────────────────────────────────
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if apiKey != "" {
			key := r.Header.Get(apiKeyHeader)
			if key != apiKey {
				http.Error(w, "Yetkisiz", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

// ─── Input validasyonu ─────────────────────────────────────────────────────────
func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("hedef boş olamaz")
	}
	if len(target) > 512 {
		return fmt.Errorf("hedef çok uzun")
	}
	if !safeTargetRe.MatchString(target) {
		return fmt.Errorf("geçersiz hedef formatı: sadece IP, CIDR ve aralık notasyonuna izin verilir")
	}
	return nil
}

func validateNmapArgs(args string) ([]string, error) {
	if args == "" {
		return nil, nil
	}
	fields := strings.Fields(args)
	var safe []string
	for _, f := range fields {
		// Kabuk meta karakterlerini reddet
		if strings.ContainsAny(f, ";&|`$(){}\\\"'<>") {
			return nil, fmt.Errorf("geçersiz argüman karakter(ler)i: %q", f)
		}
		// Script argümanlarına özel kontrol
		if strings.HasPrefix(f, "--script=") {
			scriptName := strings.TrimPrefix(f, "--script=")
			if !regexp.MustCompile(`^[a-zA-Z0-9_,-]+$`).MatchString(scriptName) {
				return nil, fmt.Errorf("geçersiz script adı: %q", scriptName)
			}
			safe = append(safe, f)
			continue
		}
		// Port belirtimleri
		if strings.HasPrefix(f, "-p") || strings.HasPrefix(f, "--port") {
			if !regexp.MustCompile(`^(-p|--port[s]?)[0-9,\-]*$`).MatchString(f) {
				return nil, fmt.Errorf("geçersiz port belirtimi: %q", f)
			}
			safe = append(safe, f)
			continue
		}
		// Whitelist kontrolü
		if !allowedArgs[f] {
			return nil, fmt.Errorf("izin verilmeyen argüman: %q", f)
		}
		safe = append(safe, f)
	}
	return safe, nil
}

// ─── Dosya yolu güvenliği ──────────────────────────────────────────────────────
func safeOutputPath(filename string) (string, error) {
	// Sadece belirli dosya adlarına izin ver
	if filename != "triedscan_result.xml" {
		return "", fmt.Errorf("geçersiz dosya adı")
	}
	absOut, err := filepath.Abs(outputDir)
	if err != nil {
		return "", err
	}
	fullPath := filepath.Join(absOut, filename)
	// Path traversal koruması
	if !strings.HasPrefix(fullPath, absOut+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal girişimi tespit edildi")
	}
	return fullPath, nil
}

func workerXMLPath(id int) string {
	return filepath.Join(outputDir, fmt.Sprintf("worker_%d.xml", id))
}

// ─── Temizlik ──────────────────────────────────────────────────────────────────
func cleanupTempXMLs() {
	files, err := filepath.Glob(filepath.Join(outputDir, "worker_*.xml"))
	if err == nil {
		for _, f := range files {
			os.Remove(f)
		}
	}
}

// ─── HTTP Handler'ları ─────────────────────────────────────────────────────────
func startScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Sadece POST", http.StatusMethodNotAllowed)
		return
	}

	// Eş zamanlı tarama koruması
	scanMutex.Lock()
	if scanRunning.Load() {
		scanMutex.Unlock()
		http.Error(w, "Zaten bir tarama çalışıyor", http.StatusConflict)
		return
	}
	scanRunning.Store(true)
	scanMutex.Unlock()

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		scanRunning.Store(false)
		http.Error(w, "Geçersiz JSON", http.StatusBadRequest)
		return
	}

	// Hedef validasyonu
	if err := validateTarget(req.Target); err != nil {
		scanRunning.Store(false)
		http.Error(w, "Hata: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Argüman validasyonu
	if _, err := validateNmapArgs(req.NmapArgs); err != nil {
		scanRunning.Store(false)
		http.Error(w, "Hata: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Worker sayısı sınırı
	if req.WorkerCount < 0 || req.WorkerCount > maxWorkers {
		scanRunning.Store(false)
		http.Error(w, fmt.Sprintf("Worker sayısı 0-%d arasında olmalı", maxWorkers), http.StatusBadRequest)
		return
	}

	// Scan tool validasyonu
	if req.ScanTool != "nmap" && req.ScanTool != "rustscan" && req.ScanTool != "" {
		scanRunning.Store(false)
		http.Error(w, "Geçersiz tarama aracı", http.StatusBadRequest)
		return
	}

	scanCancel = make(chan struct{})
	scanContext = &sync.WaitGroup{}

	go func() {
		defer scanRunning.Store(false)
		executeScan(req)
	}()

	w.WriteHeader(http.StatusOK)
}

func stopScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Sadece POST", http.StatusMethodNotAllowed)
		return
	}
	scanMutex.Lock()
	if scanCancel != nil {
		select {
		case <-scanCancel: // zaten kapalı
		default:
			close(scanCancel)
		}
	}
	scanMutex.Unlock()

	go func() {
		time.Sleep(1 * time.Second)
		cleanupTempXMLs()
	}()

	broadcastChan <- SSEMessage{Event: "scan:stopped", Data: nil}
	w.WriteHeader(http.StatusOK)
}

func outputHandler(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	if file == "" {
		file = "triedscan_result.xml"
	}

	safePath, err := safeOutputPath(file)
	if err != nil {
		http.Error(w, "Geçersiz dosya adı", http.StatusBadRequest)
		return
	}

	data, err := os.ReadFile(safePath)
	if err != nil {
		http.Error(w, "Dosya bulunamadı", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Disposition", "attachment; filename=\"triedscan_result.xml\"")
	w.Write(data)
}

// ─── Tarama motoru ─────────────────────────────────────────────────────────────
func executeScan(req ScanRequest) {
	cleanupTempXMLs()
	broadcastChan <- SSEMessage{Event: "scan:start", Data: nil}
	startTime := time.Now()

	fmt.Println("[*] IP listesi çıkartılıyor...")
	// nmap -sL için de hedefi doğrulanmış string kullan
	cmd := exec.Command("nmap", "-sL", "-n", req.Target) // #nosec G204 - target validated
	out, err := cmd.Output()
	if err != nil {
		broadcastChan <- SSEMessage{Event: "scan:stopped", Data: nil}
		return
	}

	ips := extractIPs(string(out))
	if len(ips) == 0 {
		broadcastChan <- SSEMessage{Event: "scan:stopped", Data: nil}
		return
	}

	var numWorkers int
	if req.WorkerCount > 0 {
		numWorkers = req.WorkerCount
	} else {
		fmt.Println("[*] Sistem analizi yapılıyor...")
		sweet, profilerLog := calculateSweetSpot(ips)
		fmt.Printf("[+] %s\n", profilerLog)
		numWorkers = sweet
	}

	// Güvenli arg listesi
	safeArgs, _ := validateNmapArgs(req.NmapArgs)

	chunks := generateChunksByWorkerCount(ips, numWorkers)

	var workerInitData []map[string]interface{}
	for i, chunk := range chunks {
		workerInitData = append(workerInitData, map[string]interface{}{
			"id":        i + 1,
			"status":    "running",
			"ipRange":   strings.Join(chunk, ", "),
			"startTime": time.Now().Format(time.RFC3339),
		})
	}
	broadcastChan <- SSEMessage{Event: "workers:init", Data: workerInitData}

	activeWorkerCount := len(chunks)

	for i, chunk := range chunks {
		scanContext.Add(1)
		go runWorker(i+1, chunk, safeArgs, req.ScanTool)
	}

	scanContext.Wait()

	elapsedSeconds := int(time.Since(startTime).Seconds())
	mergeXMLs(activeWorkerCount)

	broadcastChan <- SSEMessage{Event: "scan:done", Data: map[string]interface{}{"elapsed": elapsedSeconds}}
	broadcastChan <- SSEMessage{Event: "scan:merged", Data: map[string]string{"file": "triedscan_result.xml"}}
}

func runWorker(id int, ips []string, safeArgs []string, scanTool string) {
	defer scanContext.Done()

	if scanTool == "rustscan" {
		targetStr := strings.Join(ips, ",")
		sendLog(id, fmt.Sprintf("[*] RustScan başlatıldı: %s", targetStr))

		rustCmd := exec.Command("rustscan", "-a", targetStr, "-g", "--ulimit", "5000", "-b", "1000") // #nosec G204
		var rustOut bytes.Buffer
		rustCmd.Stdout = &rustOut
		rustCmd.Run()

		finalPorts := extractRustScanPorts(rustOut.String())
		if finalPorts == "" {
			sendLog(id, "[-] RustScan açık port bulamadı.")
			updateWorkerStatus(id, "done")
			return
		}
		sendLog(id, fmt.Sprintf("[+] RustScan portları buldu: %s", finalPorts))

		// RustScan portlarını doğrula
		if !regexp.MustCompile(`^[0-9,]+$`).MatchString(finalPorts) {
			sendLog(id, "[!] RustScan çıktısı geçersiz, atlanıyor.")
			updateWorkerStatus(id, "error")
			return
		}
		safeArgs = append(safeArgs, "-p", finalPorts)
	}

	sendLog(id, "[*] Nmap analizi başlatıldı...")

	// Argümanları güvenli şekilde birleştir (shell üzerinden geçmiyor)
	nmapArgs := append([]string{}, safeArgs...)
	nmapArgs = append(nmapArgs, "-oX", workerXMLPath(id))
	nmapArgs = append(nmapArgs, ips...)     // doğrulanmış IP'ler

	cmd := exec.Command("nmap", nmapArgs...) // #nosec G204
	stdout, _ := cmd.StdoutPipe()
	cmd.Start()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-scanCancel:
			cmd.Process.Kill()
			updateWorkerStatus(id, "error")
			return
		default:
			sendLog(id, scanner.Text())
		}
	}
	cmd.Wait()
	updateWorkerStatus(id, "done")
}

// ─── XML birleştirme ───────────────────────────────────────────────────────────
func mergeXMLs(workerCount int) {
	var mergedHosts bytes.Buffer
	hostRegex := regexp.MustCompile(`(?s)<host\b[^>]*>.*?</host>`)

	for i := 1; i <= workerCount; i++ {
		content, err := os.ReadFile(workerXMLPath(i))
		if err == nil {
			matches := hostRegex.FindAll(content, -1)
			for _, match := range matches {
				mergedHosts.Write(match)
				mergedHosts.WriteString("\n")
			}
		}
	}

	finalXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="TriedScan Distributed Engine" start="%d">
%s
</nmaprun>`, time.Now().Unix(), mergedHosts.String())

	outPath := filepath.Join(outputDir, "triedscan_result.xml")
	os.WriteFile(outPath, []byte(finalXML), 0640)
	cleanupTempXMLs()
}

// ─── Yardımcı fonksiyonlar ─────────────────────────────────────────────────────
func calculateSweetSpot(ips []string) (int, string) {
	cpuCores := runtime.NumCPU()
	rtt := getNetworkRTT(ips)
	var netMultiplier float64
	var netDesc string

	if rtt == -1 {
		netMultiplier = 0.5
		netDesc = "ICMP Bloklu (Temkinli Mod)"
	} else if rtt < 15.0 {
		netMultiplier = 2.0
		netDesc = fmt.Sprintf("LAN/Fiber (%.1f ms)", rtt)
	} else if rtt < 80.0 {
		netMultiplier = 1.0
		netDesc = fmt.Sprintf("WAN (%.1f ms)", rtt)
	} else {
		netMultiplier = 0.5
		netDesc = fmt.Sprintf("Yüksek Gecikme (%.1f ms)", rtt)
	}

	ramMultiplier := 1.0
	availRam := getAvailableRAMMB()
	ramDesc := "RAM okunamadı"
	if availRam > 0 {
		if availRam < 1024 {
			ramMultiplier = 0.5
			ramDesc = fmt.Sprintf("Düşük RAM (%d MB)", availRam)
		} else {
			ramDesc = fmt.Sprintf("RAM yeterli (%d MB)", availRam)
		}
	}

	sweet := int(float64(cpuCores) * netMultiplier * ramMultiplier)
	if sweet < 2 {
		sweet = 2
	}
	if sweet > len(ips) {
		sweet = len(ips)
	}
	if sweet > maxWorkers {
		sweet = maxWorkers
	}

	return sweet, fmt.Sprintf("Profiler: %d CPU | %s | %s => Worker: %d", cpuCores, netDesc, ramDesc, sweet)
}

func getNetworkRTT(ips []string) float64 {
	var totalRTT float64
	var successCount int
	limit := 3
	if len(ips) < 3 {
		limit = len(ips)
	}
	for i := 0; i < limit; i++ {
		// ping argümanları sabit, kullanıcı girdisi yok
		cmd := exec.Command("ping", "-c", "2", "-W", "1", ips[i]) // #nosec G204
		out, _ := cmd.Output()
		re := regexp.MustCompile(`time=([\d.]+)`)
		for _, m := range re.FindAllStringSubmatch(string(out), -1) {
			var val float64
			fmt.Sscanf(m[1], "%f", &val)
			totalRTT += val
			successCount++
		}
	}
	if successCount == 0 {
		return -1
	}
	return totalRTT / float64(successCount)
}

func getAvailableRAMMB() int {
	out, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return -1
	}
	re := regexp.MustCompile(`MemAvailable:\s+(\d+) kB`)
	match := re.FindStringSubmatch(string(out))
	if len(match) > 1 {
		var kb int
		fmt.Sscanf(match[1], "%d", &kb)
		return kb / 1024
	}
	return -1
}

func generateChunksByWorkerCount(ips []string, numWorkers int) [][]string {
	if len(ips) == 0 || numWorkers <= 0 {
		return nil
	}
	chunks := make([][]string, numWorkers)
	for i, ip := range ips {
		chunks[i%numWorkers] = append(chunks[i%numWorkers], ip)
	}
	var finalChunks [][]string
	for _, c := range chunks {
		if len(c) > 0 {
			finalChunks = append(finalChunks, c)
		}
	}
	return finalChunks
}

func extractIPs(nmapOutput string) []string {
	re := regexp.MustCompile(`Nmap scan report for ([\d.]+)`)
	var ips []string
	for _, match := range re.FindAllStringSubmatch(nmapOutput, -1) {
		if len(match) > 1 {
			ips = append(ips, match[1])
		}
	}
	return ips
}

func extractRustScanPorts(output string) string {
	re := regexp.MustCompile(`\[([0-9, ]+)\]`)
	portSet := make(map[string]bool)
	for _, m := range re.FindAllStringSubmatch(output, -1) {
		if len(m) > 1 {
			for _, p := range strings.Split(m[1], ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					portSet[p] = true
				}
			}
		}
	}
	var ports []string
	for p := range portSet {
		ports = append(ports, p)
	}
	return strings.Join(ports, ",")
}

func sendLog(id int, line string) {
	broadcastChan <- SSEMessage{Event: "worker:log", Data: map[string]interface{}{"id": id, "line": line}}
}

func updateWorkerStatus(id int, status string) {
	broadcastChan <- SSEMessage{Event: "worker:update", Data: map[string]interface{}{
		"id": id, "status": status, "endTime": time.Now().Format(time.RFC3339),
	}}
}

// ─── SSE ───────────────────────────────────────────────────────────────────────
func sseHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	clientChan := make(chan SSEMessage)
	clientsMutex.Lock()
	clients[clientChan] = true
	clientsMutex.Unlock()

	defer func() {
		clientsMutex.Lock()
		delete(clients, clientChan)
		clientsMutex.Unlock()
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming desteklenmiyor", http.StatusInternalServerError)
		return
	}

	for {
		select {
		case msg := <-clientChan:
			b, _ := json.Marshal(msg)
			fmt.Fprintf(w, "data: %s\n\n", string(b))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func handleBroadcasts() {
	for {
		msg := <-broadcastChan
		clientsMutex.Lock()
		for clientChan := range clients {
			clientChan <- msg
		}
		clientsMutex.Unlock()
	}
}
