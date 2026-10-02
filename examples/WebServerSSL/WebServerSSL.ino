/*
 * AsyncTCP - WebServerSSL example
 *
 * ESP32 HTTPS server using AsyncTCP + AsyncTCPTLS directly.
 * Serves a simple page and a JSON API over TLS 1.2 on port 443.
 * Uses a CA-signed cert — the same CA that signs the ClientSSL example's
 * client cert, so either example can verify the other.
 *
 * Includes a ready-to-use test PKI (key password: test123):
 *   - CA cert       — shared trust root (matches ClientSSL example)
 *   - Server cert   — signed by the CA, CN=esp32-server.local
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
 * Test with:
 *   curl -k https://<ESP32_IP>/api
 *
 * Compile with:
 *   compiler.cpp.extra_flags=-DASYNC_TCP_SSL_ENABLED=1
 */

#include <WiFi.h>
#include <AsyncTCP.h>

const char *AP_SSID     = "ESP32-AP";
const char *AP_PASSWORD = "12345678";  // min 8 chars

// CA-signed server cert — key password: test123
// Signed by "ESP32 Test CA" (same CA as ClientSSL example)
static const char SERVER_CERT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDKjCCAhKgAwIBAgIUWjOHsiza3KlO+ibKFoKusZlDomkwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNRVNQMzIgVGVzdCBDQTAeFw0yNjA4MjUyMjAzMDhaFw0z
NjA4MjIyMjAzMDhaMB0xGzAZBgNVBAMMEmVzcDMyLXNlcnZlci5sb2NhbDCCASIw
DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ54LgM4gGRTx/dPkvKCLTr/4vwk
NmNdzr7H7+iWpX/gfYwbWuGMK1kt8Uh0+Xpe+KmzP5osXXb6WiAOtwW2V3lz4oR5
ZpRHxUsR+Egt4Q+miMdMsoP4+ENH/VI3UTIURkwTNDsmBBH6t6Dejrv59AuMBRob
/QUzfWZ+5+sZGPppEMrK7UBqe+QOTX7rAelwJaWcC1lqxfRFIp9Tj83KqvDMj178
KpS0ZYEvsrYvOwhUEAG5SocP0JIPhTzLyuyx149noJyMV1s8bKi7hX3C2UejkH9d
yJNCsLiRzzMs+o/zpEM6WEQg8qMrdJY5eETjXGjnSjR3J8KrhwtZxp+QX1MCAwEA
AaNnMGUwIwYDVR0RBBwwGoISZXNwMzItc2VydmVyLmxvY2FshwTAqAQBMB0GA1Ud
DgQWBBTjuvVuucw6NeE9rdhIDxPoK3NFvjAfBgNVHSMEGDAWgBRu9+OwsLAchlQa
+OrsbMZIkI1Y1zANBgkqhkiG9w0BAQsFAAOCAQEAG5jRgelDQmkwlifEgh7AY9G4
6afVDMUxJ8d6GPRjhEYQM9jadXWaz+z0tCOo4fUbwfFxt0CBaUFfR2MEv7w7HXfY
hEydW4/Q3kMPr27f+R8kl3f34cfcOQS+RHgN87q4i+pWN2l59si/hXh7mvdmmSkd
dwQsDEtE2yvdNpQsh2ZsKJg06EM6Lb0VK89UHFP26yJ1+PG1LRy5YzoodozwkH0R
DwMOd4eGnmCfcdlgrX4teHED3rqveP0E6wCLVXRZDACtdqhfGR4v2HfX6w2pCeH9
eLW5cKlXgxh+204wb+IRHpiIgVRQONjVe2K8oF5Xtmglk6Znx0Zb/7jysMElwA==
-----END CERTIFICATE-----
)EOF";

static const char SERVER_KEY[] PROGMEM = R"EOF(
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQOk5aidzXHFPL3jnP
ZjJ44gICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEO/+XceRF3kQ/0fe
irdpEBoEggTQ2PISec4Ww7Vn+hf07GWiizPu2OiC/OzRUqBwpKytkevdOFLSAyyR
jzqhIYqB4vzarTkVocJFmhJbO3pI6DWv7n3KaiajH5DJQ6w7FJd52ix9abzlgjQd
z0rnCTQR/Cjh3y2UPgJLozfBtrKHEr6d5MSEarWCS7IkDyzTwaoTNS5aWtcl+uKz
XCVfEqXiN4AaQcHQFL36nfX63Vash7xW5VCnafpvYd9nuvms2N4eklxv8YY8FQ8Q
xI4Ql5f1G1wApR5EQKuc3jvnw7av9gcg9tiykIDWfKtp1Kw+yuWfG8HMWVVqCThU
2bZOICFALSJjw/R0LQXxl0s7stki9tkzW9WOueCYyEgjjwSmGRCJt+W677ZOLN2e
knY42ifwr45qIea/a+sJ+GvFjcfI2+skxw+VPcViB1sdWdI7aWBEiBMkgcwymZi9
uu0aY9HXJeNhpaCl556kPFoBc4kvHJ5SsDv85BDnC+WmdKkI0qjNlPwhNhjB4WpT
FO+xHp4Q5OPikSeWjYiE8uWpQQn0tzC3cxrlVEaG3fuSRld3pHvs8GbfC26f+X/0
rexm76/Gj4PV2OJpgCcu1q+QeOrvUajtdAHqmubdErP3jNNN/LFtNZUgYL6kFUKR
iaK5iRiijYFHn4pK5LHaDXd8x8D5Np5S2q60nHxhGDHmdm1xv2ZxacYX03gy4g5G
7EcBREuK2IQHLQ5hR3Rxlnxa/7L65X6pRUk2izLv1c0w+5mRNyfW8LhqpawMqMNc
EJKlzEf/z/so1Mlwm+COld3mF7mwYSiwP8isUtXx35S3YkpZ+L0PFI2kQDqdupvR
rO0P0HMGVchZtkkl40GlZ6oyZ99ZqxGkNip+ec0yeGtJcE4gEYAnORC2bZcgKM1f
B7ZCacFO64EOrmD0murajgo6xyv9i5ITrVMMXewXMl/VO65DlYScgwJtUnOHyLK+
WFmcUBSKgE89+I6nY6Q2URGC6V55GcADLL0+1EwCDmVbwWksouvh8oZWiDQDIprq
LBisfFoiBzzubIVcRutaSiQ5rBjRLWJFJjGmTxFopVIG7tHwAhqwtipf5pMR0SLA
zX7xO/cbTtKj0tIrKcRLejwegMoP/YsNueHhyAeZDmsVNVjt2XN9kydGFgNa9lO0
z1V23DUQBIWRO6SgOWceexrrMLaYVSneKD6DPq4itcZUdBcZMVX+zToZNnZAp/XO
22UvTjrmDkwfls3kK/7UA8ar1JtWSXNL5IZaWxQhylabClwrg33kE7sBe7QBIrYh
v5n+Din7H9WRY1TgJBTPSlAqLX6VBRG1S+032ZdxKtzXNhscuopV3AdVxAULMVz3
wXEWuJNtY81+nfTXseiyKFBjZTs7FufAYWhgYWk+BweagOQEGuPaH6VGXZsmuScF
3IRZmCUzWs2NIdFQA8gVq+SKdyUUq5BBm35UdrWSX5uDUFNcSW6tJpyzeM9IWClP
CtUJiwFC0aM4Q1RVxr7Jz1Q/TPAA6MMV03Ac5UGCfbRYMuJfQTklk5kQRZzsx+Sq
lTBcpdzS+qPAH9M8SQ5mz4cV1QqfCV5SCwhIAC7N/ZmYuq7/e9sEck1+Bv1CBjag
8oUFYmyM1jyCQc3l+vmXEoYItLlbjSwHfLrzywLXrTn2iwdt2alQE00=
-----END ENCRYPTED PRIVATE KEY-----
)EOF";

AsyncServer *sslServer = NULL;

static void sendResponse(AsyncClient *client, int code, const char *contentType,
                         const char *body, size_t bodyLen) {
  char header[128];
  int headerLen = snprintf(header, sizeof(header),
    "HTTP/1.1 %s\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %u\r\n"
    "Connection: close\r\n"
    "\r\n",
    code == 200 ? "200 OK" : "301 Moved",
    contentType, (unsigned)bodyLen);
  client->write(header, headerLen);
  client->write(body, bodyLen);
}

static const char INDEX_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WebServerSSL</title>
  <style>
    body { font-family: sans-serif; text-align: center; padding: 2em; }
    h1 { color: #2c3e50; }
    a { color: #2980b9; }
  </style>
</head>
<body>
  <h1>WebServerSSL</h1>
  <p>HTTPS is working!</p>
  <p><a href="/api">/api</a> - JSON endpoint</p>
</body>
</html>
)rawliteral";

void onClient(void *arg, AsyncClient *client) {
  if (!client) return;

  client->onData([](void *arg, AsyncClient *client, void *data, size_t len) {
    String request((const char *)data, len);

    if (request.startsWith("GET /api")) {
      char json[128];
      int jsonLen = snprintf(json, sizeof(json),
        "{\"status\":\"ok\",\"heap\":%u,\"uptime\":%lu}",
        ESP.getFreeHeap(), millis() / 1000);
      sendResponse(client, 200, "application/json", json, jsonLen);
    } else {
      sendResponse(client, 200, "text/html", INDEX_PAGE, sizeof(INDEX_PAGE) - 1);
    }
    client->close();
  });

  client->onError([](void *arg, AsyncClient *client, int8_t error) {
    Serial.printf("Connection error: %d\n", error);
    delete client;
  });

  client->onDisconnect([](void *arg, AsyncClient *client) {
    delete client;
  });
}

void setup() {
  Serial.begin(115200);
  delay(500);

  WiFi.softAP(AP_SSID, AP_PASSWORD);
  delay(500);
  Serial.printf("\nAP SSID: %s  IP: %s\n", AP_SSID, WiFi.softAPIP().toString().c_str());

  sslServer = new AsyncServer(443);
  sslServer->onClient(onClient, NULL);
  sslServer->beginSecure(SERVER_CERT, SERVER_KEY, "test123");

  Serial.printf("[Server] HTTPS on port 443\n");
  Serial.printf("Test: curl -k https://%s/api\n",
                WiFi.softAPIP().toString().c_str());
}

void loop() {
  delay(10000);
}
