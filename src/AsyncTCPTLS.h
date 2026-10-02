#pragma once

#if ASYNC_TCP_SSL_ENABLED

// --- mbedTLS version abstraction -----------------------------------------
// Mbed TLS v3 (stable Arduino core 3.x): legacy entropy + CTR-DRBG RNG.
// Mbed TLS v4 (dev core / ESP-IDF 6.0): PSA Crypto; entropy/ctr_drbg headers
// and app-supplied RNG callbacks were removed.
#include "mbedtls/build_info.h"   // defines MBEDTLS_VERSION_MAJOR on v3/v4
#ifndef MBEDTLS_VERSION_MAJOR
#define MBEDTLS_VERSION_MAJOR 3
#endif
#define ASYNCTCP_MBEDTLS_MAJOR MBEDTLS_VERSION_MAJOR
// -------------------------------------------------------------------------

#include "mbedtls/platform.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#if ASYNCTCP_MBEDTLS_MAJOR < 4
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#endif
#include "mbedtls/error.h"
#include "mbedtls/pem.h"

struct tcp_pcb;

#define ASYNCTCP_TLS_CAN_RETRY(r)   (((r) == MBEDTLS_ERR_SSL_WANT_READ) || ((r) == MBEDTLS_ERR_SSL_WANT_WRITE))
#define ASYNCTCP_TLS_EOF(r)         (((r) == MBEDTLS_ERR_SSL_CONN_EOF) || ((r) == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY))

#define ASYNCTCP_TLS_RX_BUF_SIZE    4096
#define ASYNCTCP_TLS_RX_BUF_MAX     8192

#ifndef SSL_HANDSHAKE_TIMEOUT
#define SSL_HANDSHAKE_TIMEOUT 10000
#endif

#ifndef SSL_MAX_CONNECTIONS
#define SSL_MAX_CONNECTIONS 4
#endif

class AsyncTCPTLS
{
private:
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;

    // Shared RNG — initialized once, serialized on async task.
    // v3: legacy entropy + CTR-DRBG. v4: PSA Crypto (no DRBG types).
#if ASYNCTCP_MBEDTLS_MAJOR < 4
    static mbedtls_ctr_drbg_context drbg_ctx;
    static mbedtls_entropy_context entropy_ctx;
#endif
    static bool _conf_initialized;

    static int _rng_init(void);
#if ASYNCTCP_MBEDTLS_MAJOR < 4
    static void _rng_seed_and_set(void);
#endif
    // Parse a PEM/DER private key. v3 supplies the legacy RNG; v4 uses PSA.
    static int _parse_private_key(mbedtls_pk_context *pk,
        const unsigned char *key, size_t keylen,
        const unsigned char *pwd, size_t pwdlen);

    // Concurrent connection tracking
    static int _active_count;

    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;
    bool _have_ca_cert;
    bool _have_client_cert;
    bool _have_client_key;

    unsigned long handshake_timeout;
    unsigned long handshake_start_time;

    tcp_pcb *_pcb;

    // PEM password for encrypted private keys (owned copy via strdup)
    char *_ssl_key_password;

    // Per-connection encrypted data buffers for BIO callbacks
    unsigned char *_ssl_rx_buf;
    size_t _ssl_rx_buf_capacity;  // current allocation size (grows via realloc)
    size_t _ssl_rx_buf_len;
    size_t _ssl_rx_pos;

    int _startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const unsigned char *rootCABuff, const size_t rootCABuff_len,
        const unsigned char *cli_cert, const size_t cli_cert_len,
        const unsigned char *cli_key, const size_t cli_key_len,
        const char *pskIdent, const char *psKey,
        const char *keyPassword = NULL);

    void _deleteHandshakeCerts(void);

public:
    AsyncTCPTLS(void);
    virtual ~AsyncTCPTLS();

    // Feed encrypted data from TCP into BIO buffer (returns false if buffer full)
    bool feedRxData(const unsigned char *data, size_t len);
    size_t rxBufLen() const { return _ssl_rx_buf_len - _ssl_rx_pos; }

    // Check if BIO has buffered rx data available
    bool hasRxData(void) const { return _ssl_rx_buf && (_ssl_rx_pos < _ssl_rx_buf_len); }

    // Public accessor for PCB (needed by BIO callbacks)
    tcp_pcb *pcb() const { return _pcb; }

    // Diagnostic: log BIO buffer state
    void logBioState(const char *tag) const;

    static int getActiveCount() { return _active_count; }

    int startSSLClientInsecure(tcp_pcb *pcb, const char *host_or_ip);

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    int startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const char *pskIdent, const char *psKey);
#endif

    int startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const char *rootCABuff,
        const char *cli_cert,
        const char *cli_key,
        const char *keyPassword = NULL);

    int startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const unsigned char *rootCABuff, const size_t rootCABuff_len,
        const unsigned char *cli_cert, const size_t cli_cert_len,
        const unsigned char *cli_key, const size_t cli_key_len,
        const char *keyPassword = NULL);

    int startSSLServer(tcp_pcb *pcb,
        const unsigned char *server_cert, size_t server_cert_len,
        const unsigned char *server_key, size_t server_key_len,
        const char *password = NULL);

    int runSSLHandshake(void);

    int write(const uint8_t *data, size_t len);

    int read(uint8_t *data, size_t len);

    // Decrypt application data via mbedtls_ssl_read (BIO pulls encrypted bytes internally)
    int sslRead(uint8_t *data, size_t len);

    // Send TLS close_notify alert and flush to TCP
    void sendCloseNotify(void);
};

#endif // ASYNC_TCP_SSL_ENABLED
