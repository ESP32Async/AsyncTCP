/*
 * AsyncTCP - ClientSSL example
 *
 * ESP32 HTTPS client with mutual TLS (mTLS) using AsyncTCP + AsyncTCPTLS.
 * Connects to a server, presents a client certificate, and verifies the
 * server using a shared CA. The server must request client certificates
 * for mTLS to take effect.
 *
 * Includes a ready-to-use test PKI (key password: test123):
 *   - CA cert   — shared trust root for both client and server
 *   - Client cert + key — presented to the server during handshake
 *
 * Regenerate the full PKI:
 *   # CA
 *   openssl req -x509 -newkey rsa:2048 -passout pass:test123 \
 *     -keyout ca.key -out ca.pem -days 3650 -subj "/CN=ESP32 Test CA"
 *
 *   # Server (signed by CA)
 *   openssl req -newkey rsa:2048 -passout pass:test123 \
 *     -keyout server.key -out server.csr -subj "/CN=esp32-server.local"
 *   openssl x509 -req -in server.csr -CA ca.pem -passin pass:test123 \
 *     -CAkey ca.key -CAcreateserial -out server.pem -days 3650 \
 *     -extfile <(printf "subjectAltName=DNS:esp32-server.local,IP:192.168.4.1")
 *
 *   # Client (signed by CA)
 *   openssl req -newkey rsa:2048 -passout pass:test123 \
 *     -keyout client.key -out client.csr -subj "/CN=esp32-client"
 *   openssl x509 -req -in client.csr -CA ca.pem -passin pass:test123 \
 *     -CAkey ca.key -CAcreateserial -out client.pem -days 3650
 *
 * To test, run a server that requests client certs, e.g.:
 *   openssl s_server -cert server.pem -key server.key \
 *     -pass pass:test123 -CAfile ca.pem -Verify 1 -www -port 4433
 *
 * Compile with:
 *   compiler.cpp.extra_flags=-DASYNC_TCP_SSL_ENABLED=1
 */

#include <WiFi.h>
#include <AsyncTCP.h>

const char *SSID     = "ESP32-AP";
const char *PASSWORD = "12345678";

// -- Server to connect to -------------------------------------------
const char *SERVER_HOST = "192.168.4.1";
const uint16_t SERVER_PORT = 443;

// -- CA certificate (verifies the server) --------------------------
// Shared trust root — signed both the server and client certs.
static const char CA_CERT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDETCCAfmgAwIBAgIUYBESfy7ki1nvGjMvvvBRQZAxr7wwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNRVNQMzIgVGVzdCBDQTAeFw0yNjA4MjUyMjAzMDhaFw0z
NjA4MjIyMjAzMDlaMBgxFjAUBgNVBAMMDUVTUDMyIFRlc3QgQ0EwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC3h61RZ+58l8hPMKXUigsXWB+4DYCJQEBM
zUIAMitu16rV4JqD7AGZISRoSZTGrxjZOGScvj0RGx2e4Oj0v30lzKxVu0DrOUpd
RY2tcdH1AzsV2XYuJbbPSrq5xGjIX34jmYrD7zPjGAvCHehfJWVIYqCCrtWVPfTE
KcxSaZ/5HW5vua6XUS6Ub/L6Qo/QlAF1tI3sk+HV5HbwIuoQcfPopohrWLdGopPQ
1EdMYXccKdsYLV8IR2WMbDmAJlAsDWtl7YICdkUz5k4rh/q9EV48698BNEpyxEHj
rcbLnXrqQtGxYCMts5p9FeT9T95SpEEH6NjrToK71bi0pYGDxm/rAgMBAAGjUzBR
MB0GA1UdDgQWBBRu9+OwsLAchlQa+OrsbMZIkI1Y1zAfBgNVHSMEGDAWgBRu9+Ow
sLAchlQa+OrsbMZIkI1Y1zAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQBYEOtModTG0OSGYk5ccrPYQqGcyaU6HZsDQHHWcoTSnhu+I3zIXPtQUffa
fM0T7+c/zWLkrLYr5Qphv0dPDc3YmTGO7IYcYLEnmFWsHbekKQNEruU0qoKwJhRa
p/tWlvDMCPDTavHQMXm2frvVq0uPMcEDiCfeffZSyMWrzVA06IuWuzdslX81KqIJ
WNjp/QUIa9p3XW47Uus/gV+hE12D/7WoR5iBXjttBQ5soafLSo8rBOZZ4noHbHl5
DM+p2VJc/xX1z+NovEsSNjo3j/2buo/VT1s268yUlGmXMLmdnQkWqAqpJcfXEWmM
ak1VKOrDAFKqocv9/aFKD/UYXXjD
-----END CERTIFICATE-----
)EOF";

// -- Client certificate (presented to the server) -------------------
// Signed by the CA above. The server uses this to authenticate us.
static const char CLIENT_CERT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUWjOHsiza3KlO+ibKFoKusZlDomowDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNRVNQMzIgVGVzdCBDQTAeFw0yNjA4MjUyMjAzMDhaFw0z
NjA4MjIyMjAzMDhaMBcxFTATBgNVBAMMDGVzcDMyLWNsaWVudDCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMlwU6IT2Co6mFt8MDNc8apojJVuqhKx3RfI
+SR+3tJv3CI+lvf+smrvRINpEcESY7s2bMfwjhemfZ8aUyeye/xVxtuoH+JCa5Zg
nRWwM46V2TjsfmJBpQkmlZfv3laklBAkZpw3xrIL66zIwfqIynSmXBgN8PnGSsoC
jpN0t2pBVr/p1zxB5G76RMhYO9Eua2IEF1JsVUQ+/dih2a9RaSbWhWaLD2kbG/6m
T/vtZOTNULGggcxJRJgULkpsBCaTMGi1zUAzKVWL9KkulAxOlcNOapPJ7Xel1Jrq
8XOPQHB9MPpjOgiUnWt8IAdL0YCSpAsy5j7kxjg3W1fpQZre+CUCAwEAAaNCMEAw
HQYDVR0OBBYEFO8F1UueWWPj/6JewZ99AlXAi7zSMB8GA1UdIwQYMBaAFG7347Cw
sByGVBr46uxsxkiQjVjXMA0GCSqGSIb3DQEBCwUAA4IBAQBpn+tFzK588Hh/XPB/
ptLInacSREi0AL9I2d9DJ4h9BxDw3d3Sjo3UTrUnOEovjUqiBkAyFW9ymSu6GYAI
Ll5IN4ZcHE+VwtnG5ncaqVE0mzT/81Whs6JCH7RMnhfBA7Cv+N8F5Jw0RXHns+yw
n8t6pQsj1pTGeRs1Twdu7+xO/m2iRu4iCSgpIuXdJvd7dOTHG12zyAN37V/PSdBg
VnlFbpZyYIoQmpZ+KhW4/05nUqzvncA9+DqJ2nh5Gn+7djQkWnUSxAin/+F7+pZp
/pCnwlOJ9zxmraFATp982R0GXqka5JiMEfH+J2p0OokRZ+ZWRsT6cTwOFDCviZXu
UOOh
-----END CERTIFICATE-----
)EOF";

// -- Client private key (encrypted, password: test123) ----------------
static const char CLIENT_KEY[] PROGMEM = R"EOF(
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQI4Sut7buwL2xN7ZC
XzI6uQICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEP7SbAUYIB8Tdwtb
sNGaBRYEggTQbv4XQxi36jLdzJuBkeOs6/DQP7SW4wuVQkqOzZuhWLyaSFKrbciq
fpv+cpqFvZHalMxj3Avuh/rjsZPdOKwo+wcfYoGnA76bF01sL2SFHkrkDA49BNcq
YAYiyYpl3w3Pw66iBhyeiLzbOohPipSrdwbGZvHdqnZ/7hF9CCFLFrKsy4ztiq7I
xuU2wYkAAz6FjRlERub4TY7HK4yTFLJ+wQR5vx1VRyXHkSK4F1rvcEIjh71v1hHC
xbkKEPM71sxjFWPerQS7lFJA5B90rgK0DFNG3HlHSBqFqs0TsdRKf3EaqJVdI939
bbIrPeAV8cyxYwOGJzbbKOV0zU2MGDQG2lHtssk+TagN/jiXBlfYlal2nWXKHgAS
CZFpTpCCBldG44cg+mgWt/hEZVtctxxBpDcDi/aOTwX1kOzVplw+hm6TpGgo3rKB
XhlTLmZLvEk8fmnr4SB+1lWuu5LmsdDP2RWtU48SL8pRCuCEUOMEQCjYV050lXJ+
jbutA2/rHLVGjfiilG8gCMrbdHVtEORDB2MjXzH597PgKCQJzrtPSxgL9QZoCXhL
QRhCa1nc0vFmyL8fPkcV35lBN+IfIJmrbO5NI14ZChwG5VkApttz7TJB9Yg2tbYF
VdoPMzSwZ2rWuS+rwBfFCWDmCcJvdxGcHiCtQN+mKx9vyao9fOAGjKiOiP7FPMfu
DMJNwJyjSFcXDNPUjt1GbUsgNA+aj6sj2lHu2YHiOpnMrkJAcT3B0pvO4qDUGeIC
y7oKrPspPAKLV6wac0UNe9dqGShEtWO4EXrPZ6EqAoV85yHzizGqVWGMkZ2SS1m5
YCAKL43V+tgspJ1wQQHiGeIJe75qj8dnnGfdCH8ukvQhLjByAzWFcxV+E53Qncq7
zriPNsNfFchw2crm9BgGnTgo2GD2wmMPfMqSwR2EjWFB2w3ROJhfSKwZ4PmGqu4R
sDIeqxSJGr1/6OwqPQJfsh8QojZ/6sSPJ4neRJ4oXIv0Jx2N6kyCIf7Njc+/McXg
AY0Zecrev46ii3JSpmXp8JHGLTFsshZepdqZCv8Ip+J0ZKgkTStZg3dRUuM4nati
Zcj1tZKCxpdbIkV+NSMQpeWqyGfShhZn9QHiPWplWqZQd1RgutSOK5CyFsUN+3Z2
XqUO7z7inh846pPU1403oDGsdye96Fd3enYd+gZA/sT5onhOj3SBIqkM8PtTtmWF
uNz0LrYVL0HqdRRLjMlYVUDyzcGxoYay5jk0NrEL8CRUwKjQ/+/M5NfqDpvnJ6+2
MZaIBCTUh9sOa7dBk4MUpYsz9IPTul9BlUh/R9JUqlUEelWwvMg3Z/CQNtqy/+Xp
R0WyusRbHrD06iquvLOwN2RLgKQ9fxxcNMuy8vcBLESd2XaYuA4zYpaif1KiUGd7
mXrl9KnWSfFPzALUsDIs+TDzoL4LU6LTxj27MwaoOPsAhYmLcArIXUzx312tWNW/
rrSdVTqATqPkG4Fwr91oHKGrXFe+VpNrWMia8ZkLVOSIPdaeLbonmJtSF31Nrum4
9tGI7kqTLVCxp0IoeIhoMv4pvnMP5IioxL9du2kua9Kl17sruZzogzs6SewVfHNS
ndEmp7FQtj5TMYqfXM0aWtoFMyJPFVYusJBl+cK6R2DGon7GKsxTjVA=
-----END ENCRYPTED PRIVATE KEY-----
)EOF";

AsyncClient *sslClient = NULL;

void onConnected(void *arg, AsyncClient *client) {
  Serial.println("[Client] TLS handshake complete — sending request");

  char request[128];
  snprintf(request, sizeof(request),
      "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", SERVER_HOST);
  client->write(request, strlen(request));
}

void onData(void *arg, AsyncClient *client, void *data, size_t len) {
  Serial.printf("[Client] Received %u bytes:\n", len);
  Serial.write((const uint8_t *)data, len);
  Serial.println();
}

void onDisconnect(void *arg, AsyncClient *client) {
  Serial.println("[Client] Disconnected");
}

void onError(void *arg, AsyncClient *client, int8_t error) {
  Serial.printf("[Client] Error %d: %s\n", error,
                client->errorToString(error));
}

void setup() {
  Serial.begin(115200);
  delay(500);

  WiFi.begin(SSID, PASSWORD);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf("\nIP: %s\n", WiFi.localIP().toString().c_str());

  sslClient = new AsyncClient();
  sslClient->onConnect(onConnected);
  sslClient->onData(onData);
  sslClient->onDisconnect(onDisconnect);
  sslClient->onError(onError);

  Serial.printf("[Client] Connecting to %s:%u\n", SERVER_HOST, SERVER_PORT);

  // --- With server verification (recommended) ---
  bool ok = sslClient->beginSecure(
      SERVER_HOST, SERVER_PORT,
      CA_CERT,
      CLIENT_CERT, CLIENT_KEY,
      "test123");

  // --- Without server verification (skip CA check) ---
  // WARNING: do NOT use in production — defeats the purpose of TLS.
  // bool ok = sslClient->beginSecure(
  //     SERVER_HOST, SERVER_PORT,
  //     NULL,              // no CA — server cert is not verified
  //     CLIENT_CERT, CLIENT_KEY,
  //     "test123");

  if (!ok) {
    Serial.println("[Client] beginSecure failed");
    delete sslClient;
    sslClient = NULL;
    return;
  }
}

void loop() {
  delay(10000);
}
