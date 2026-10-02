// SPDX-License-Identifier: LGPL-3.0-or-later
// SSL/TLS support for AsyncTCP using mbedTLS over LwIP raw TCP (tcp_pcb)
// Custom BIO callbacks replace BSD socket mbedtls_net_send/mbedtls_net_recv

#if ASYNC_TCP_SSL_ENABLED

#include <Arduino.h>
#include "AsyncTCPLogging.h"
#include <mbedtls/pem.h>

extern "C" {
#include "lwip/tcp.h"
}

#include "AsyncTCPTLS.h"

#if !defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) && !defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
#  warning "PSK ciphersuites not configured — PSK TLS overloads will be unavailable"
#endif


// From mbedtls/net_sockets.h — not included since we use custom LwIP BIO
#ifndef MBEDTLS_ERR_NET_SEND_FAILED
#define MBEDTLS_ERR_NET_SEND_FAILED -0x004E
#endif

static int _handle_error(int err) {
    if (err == -30848) {
        return err;
    }
    // Suppress connection reset — normal client disconnect
    if (err == -0x004E) {
        return err;
    }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror(err, error_buf, 100);
    async_tcp_log_e("(%d) %s", err, error_buf);
#else
    async_tcp_log_e("code %d", err);
#endif
    return err;
}

#define handle_error(e) _handle_error(e)

#include "lwip/priv/tcpip_priv.h"

typedef struct {
    struct tcpip_api_call_data call;
    tcp_pcb *pcb;
    const void *data;
    size_t size;
    uint8_t apiflags;
    err_t err;
} ssl_tcp_api_call_t;

static err_t _tcp_ssl_write_api(struct tcpip_api_call_data *api_call_msg) {
    ssl_tcp_api_call_t *msg = (ssl_tcp_api_call_t *)api_call_msg;
    msg->err = tcp_write(msg->pcb, msg->data, msg->size, msg->apiflags);
    if (msg->err == ERR_OK) {
        msg->err = tcp_output(msg->pcb);
    }
    return msg->err;
}

static err_t _tcp_ssl_write(tcp_pcb *pcb, const void *data, size_t size, uint8_t apiflags) {
    if (!pcb) return ERR_CONN;
    ssl_tcp_api_call_t msg;
    msg.pcb = pcb;
    msg.data = data;
    msg.size = size;
    msg.apiflags = apiflags;
    msg.err = ERR_CONN;
    if (tcpip_api_call(_tcp_ssl_write_api, (struct tcpip_api_call_data *)&msg) != ERR_OK) {
        return ERR_CONN;
    }
    return msg.err;
}

/*
 * Custom LwIP BIO callbacks for mbedTLS
 * These bridge mbedTLS's I/O with LwIP raw TCP (tcp_pcb).
 * The void* ctx points to the AsyncTCPTLS instance.
 */

static int _lwip_ssl_send(void *ctx, const unsigned char *buf, size_t len) {
    AsyncTCPTLS *sslctx = (AsyncTCPTLS *)ctx;
    if (!sslctx || !sslctx->pcb()) {
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    tcp_pcb *pcb = sslctx->pcb();

    err_t err = _tcp_ssl_write(pcb, buf, len, TCP_WRITE_FLAG_COPY);
    if (err == ERR_OK) {
        return (int)len;
    }
    if (err == ERR_MEM) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int _lwip_ssl_recv(void *ctx, unsigned char *buf, size_t len) {
    AsyncTCPTLS *sslctx = (AsyncTCPTLS *)ctx;
    if (!sslctx || !sslctx->hasRxData()) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    return sslctx->read(buf, len);
}

#if ASYNCTCP_MBEDTLS_MAJOR >= 4
// v4: RNG params removed — PSA Crypto provides the RNG internally.
int AsyncTCPTLS::_parse_private_key(mbedtls_pk_context *pk,
        const unsigned char *key, size_t keylen,
        const unsigned char *pwd, size_t pwdlen) {
    return mbedtls_pk_parse_key(pk, key, keylen, pwd, pwdlen);
}
#else
int AsyncTCPTLS::_parse_private_key(mbedtls_pk_context *pk,
        const unsigned char *key, size_t keylen,
        const unsigned char *pwd, size_t pwdlen) {
    return mbedtls_pk_parse_key(pk, key, keylen, pwd, pwdlen,
                                mbedtls_ctr_drbg_random, &drbg_ctx);
}
#endif

/*
 * AsyncTCPTLS implementation
 */

// Static shared RNG — initialized once, serialized on async task
#if ASYNCTCP_MBEDTLS_MAJOR < 4
mbedtls_ctr_drbg_context AsyncTCPTLS::drbg_ctx;
mbedtls_entropy_context AsyncTCPTLS::entropy_ctx;
#endif
bool AsyncTCPTLS::_conf_initialized = false;
int AsyncTCPTLS::_active_count = 0;

#if ASYNCTCP_MBEDTLS_MAJOR >= 4
// Mbed TLS v4: PSA Crypto provides the RNG internally, so no app RNG is
// needed. We only have to ensure PSA is initialised (see _rng_init).
#include <psa/crypto.h>
#endif

int AsyncTCPTLS::_rng_init(void) {
    if (_conf_initialized) return 0;
#if ASYNCTCP_MBEDTLS_MAJOR >= 4
    psa_status_t ps = psa_crypto_init();
    if (ps != PSA_SUCCESS) {
        async_tcp_log_e("psa_crypto_init failed: %d", (int)ps);
        return -1;
    }
    _conf_initialized = true;
#else
    _rng_seed_and_set();
    _conf_initialized = true;
#endif
    return 0;
}

#if ASYNCTCP_MBEDTLS_MAJOR < 4
void AsyncTCPTLS::_rng_seed_and_set(void) {
    mbedtls_ctr_drbg_init(&drbg_ctx);
    mbedtls_entropy_init(&entropy_ctx);
    mbedtls_ctr_drbg_seed(&drbg_ctx, mbedtls_entropy_func,
                          &entropy_ctx, (const unsigned char *)"AsyncTCPTLS", 11);
}
#endif

AsyncTCPTLS::AsyncTCPTLS(void) {
    mbedtls_ssl_init(&ssl_ctx);
    mbedtls_ssl_config_init(&ssl_conf);
    if (_rng_init() != 0) {
        async_tcp_log_e("AsyncTCPTLS RNG init failed");
    }
    _pcb = NULL;
    _ssl_key_password = NULL;
    _have_ca_cert = false;
    _have_client_cert = false;
    _have_client_key = false;
    handshake_timeout = SSL_HANDSHAKE_TIMEOUT;
    handshake_start_time = 0;

    _ssl_rx_buf = (unsigned char *)malloc(ASYNCTCP_TLS_RX_BUF_SIZE);
    _ssl_rx_buf_capacity = _ssl_rx_buf ? ASYNCTCP_TLS_RX_BUF_SIZE : 0;
    _ssl_rx_buf_len = 0;
    _ssl_rx_pos = 0;

    _active_count++;
}

AsyncTCPTLS::~AsyncTCPTLS() {
    _deleteHandshakeCerts();

    async_tcp_log_v("~AsyncTCPTLS");

    mbedtls_ssl_free(&ssl_ctx);
    mbedtls_ssl_config_free(&ssl_conf);

    if (_ssl_key_password) {
        free((void*)_ssl_key_password);
        _ssl_key_password = NULL;
    }

    if (_ssl_rx_buf) {
        free(_ssl_rx_buf);
        _ssl_rx_buf = NULL;
    }

    _active_count--;
}

bool AsyncTCPTLS::feedRxData(const unsigned char *data, size_t len) {
    if (!_ssl_rx_buf || len == 0) return true;

    // Only compact when there's not enough room at the tail
    size_t free_at_tail = _ssl_rx_buf_capacity - _ssl_rx_buf_len;
    if (len > free_at_tail && _ssl_rx_pos > 0) {
        size_t remaining = _ssl_rx_buf_len - _ssl_rx_pos;
        if (remaining > 0) {
            memmove(_ssl_rx_buf, _ssl_rx_buf + _ssl_rx_pos, remaining);
        }
        _ssl_rx_buf_len = remaining;
        _ssl_rx_pos = 0;
        free_at_tail = _ssl_rx_buf_capacity - _ssl_rx_buf_len;
    }

    // Check hard cap — if exceeded, caller must hold the pbuf
    if (_ssl_rx_buf_len + len > ASYNCTCP_TLS_RX_BUF_MAX) {
        return false;
    }

    // Grow buffer if needed (up to cap)
    if (len > free_at_tail) {
        size_t need = _ssl_rx_buf_len + len;
        unsigned char *newbuf = (unsigned char *)realloc(_ssl_rx_buf, need);
        if (!newbuf) return false;
        _ssl_rx_buf = newbuf;
        _ssl_rx_buf_capacity = need;
    }
    memcpy(_ssl_rx_buf + _ssl_rx_buf_len, data, len);
    _ssl_rx_buf_len += len;
    return true;
}

int AsyncTCPTLS::startSSLClientInsecure(tcp_pcb *pcb, const char *host_or_ip) {
    return _startSSLClient(pcb, host_or_ip,
        NULL, 0,
        NULL, 0,
        NULL, 0,
        NULL, NULL);
}

int AsyncTCPTLS::startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const char *pskIdent, const char *psKey) {
    return _startSSLClient(pcb, host_or_ip,
        NULL, 0,
        NULL, 0,
        NULL, 0,
        pskIdent, psKey);
}

int AsyncTCPTLS::startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const char *rootCABuff,
        const char *cli_cert,
        const char *cli_key,
        const char *keyPassword) {
    return startSSLClient(pcb, host_or_ip,
        (const unsigned char *)rootCABuff, (rootCABuff != NULL) ? strlen(rootCABuff) + 1 : 0,
        (const unsigned char *)cli_cert, (cli_cert != NULL) ? strlen(cli_cert) + 1 : 0,
        (const unsigned char *)cli_key, (cli_key != NULL) ? strlen(cli_key) + 1 : 0,
        keyPassword);
}

int AsyncTCPTLS::startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const unsigned char *rootCABuff, const size_t rootCABuff_len,
        const unsigned char *cli_cert, const size_t cli_cert_len,
        const unsigned char *cli_key, const size_t cli_key_len,
        const char *keyPassword) {
    return _startSSLClient(pcb, host_or_ip,
        rootCABuff, rootCABuff_len,
        cli_cert, cli_cert_len,
        cli_key, cli_key_len,
        NULL, NULL,
        keyPassword);
}

int AsyncTCPTLS::_startSSLClient(tcp_pcb *pcb, const char *host_or_ip,
        const unsigned char *rootCABuff, const size_t rootCABuff_len,
        const unsigned char *cli_cert, const size_t cli_cert_len,
        const unsigned char *cli_key, const size_t cli_key_len,
        const char *pskIdent, const char *psKey,
        const char *keyPassword) {
    int ret;

    if (!pcb) {
        return -1;
    }

    async_tcp_log_v("Setting up the SSL/TLS structure...");

    if ((ret = mbedtls_ssl_config_defaults(&ssl_conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        return handle_error(ret);
    }

    // Force TLS 1.2 only
    mbedtls_ssl_conf_min_tls_version(&ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);

    // Disable renegotiation
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(&ssl_conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif

    // Pin fast cipher suite — hardware-accelerated AES-GCM + SHA256 on ESP32
    static const int client_ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        0
    };
    mbedtls_ssl_conf_ciphersuites(&ssl_conf, client_ciphersuites);

    if (rootCABuff != NULL) {
        async_tcp_log_v("Loading CA cert");
        mbedtls_x509_crt_init(&ca_cert);
        mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        ret = mbedtls_x509_crt_parse(&ca_cert, rootCABuff, rootCABuff_len);
        _have_ca_cert = true;
        mbedtls_ssl_conf_ca_chain(&ssl_conf, &ca_cert, NULL);
        if (ret < 0) {
            _deleteHandshakeCerts();
            return handle_error(ret);
        }
    } else if (pskIdent != NULL && psKey != NULL) {
#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) || defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
        async_tcp_log_v("Setting up PSK");
        if ((strlen(psKey) & 1) != 0 || strlen(psKey) > 2 * MBEDTLS_PSK_MAX_LEN) {
            async_tcp_log_e("pre-shared key not valid hex or too long");
            return -1;
        }
        unsigned char psk[MBEDTLS_PSK_MAX_LEN];
        size_t psk_len = strlen(psKey) / 2;
        for (size_t j = 0; j < strlen(psKey); j += 2) {
            char c = psKey[j];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j / 2] = c << 4;
            c = psKey[j + 1];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j / 2] |= c;
        }
        ret = mbedtls_ssl_conf_psk(&ssl_conf, psk, psk_len,
                (const unsigned char *)pskIdent, strlen(pskIdent));
        mbedtls_platform_zeroize(psk, sizeof(psk));
        if (ret != 0) {
            async_tcp_log_e("mbedtls_ssl_conf_psk returned %d", ret);
            return handle_error(ret);
        }
#else
        async_tcp_log_e("PSK ciphersuites not enabled in mbedTLS config");
        return -1;
#endif
    } else {
        // No CA cert, no PSK — skip server verification
        mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
        async_tcp_log_i("WARNING: Skipping SSL Verification. INSECURE!");
    }

    if (rootCABuff != NULL && cli_cert != NULL && cli_key != NULL) {
        mbedtls_x509_crt_init(&client_cert);
        mbedtls_pk_init(&client_key);

        async_tcp_log_v("Loading CRT cert");
        ret = mbedtls_x509_crt_parse(&client_cert, cli_cert, cli_cert_len);
        _have_client_cert = true;
        if (ret < 0) {
            _deleteHandshakeCerts();
            return handle_error(ret);
        }

        async_tcp_log_v("Loading private key");
        if (_ssl_key_password) { free((void*)_ssl_key_password); _ssl_key_password = NULL; }
        _ssl_key_password = keyPassword ? strdup(keyPassword) : NULL;
        const unsigned char *pwd = (const unsigned char *)_ssl_key_password;
        size_t pwd_len = _ssl_key_password ? strlen(_ssl_key_password) : 0;
        ret = _parse_private_key(&client_key, cli_key, cli_key_len, pwd, pwd_len);
        _have_client_key = true;
        if (ret != 0) {
            _deleteHandshakeCerts();
            return handle_error(ret);
        }

        mbedtls_ssl_conf_own_cert(&ssl_conf, &client_cert, &client_key);
    }

    async_tcp_log_v("Setting hostname for TLS session...");
    if (!host_or_ip || strlen(host_or_ip) > 253) {
        _deleteHandshakeCerts();
        async_tcp_log_e("Invalid hostname (too long or NULL)");
        return -1;
    }
    if ((ret = mbedtls_ssl_set_hostname(&ssl_ctx, host_or_ip)) != 0) {
        _deleteHandshakeCerts();
        return handle_error(ret);
    }

#if ASYNCTCP_MBEDTLS_MAJOR < 4
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &drbg_ctx);
#endif

    // Reduce buffer sizes to fit ESP32 heap (requires MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    mbedtls_ssl_conf_max_frag_len(&ssl_conf, MBEDTLS_SSL_MAX_FRAG_LEN_4096);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl_ctx, &ssl_conf)) != 0) {
        _deleteHandshakeCerts();
        return handle_error(ret);
    }

    _pcb = pcb;
    // Set BIO: ctx is this context (used by both send and recv callbacks)
    mbedtls_ssl_set_bio(&ssl_ctx, this, _lwip_ssl_send, _lwip_ssl_recv, NULL);
    handshake_start_time = 0;

    return 0;
}

int AsyncTCPTLS::startSSLServer(tcp_pcb *pcb,
        const unsigned char *server_cert, size_t server_cert_len,
        const unsigned char *server_key, size_t server_key_len,
        const char *password) {
    int ret;

    if (server_cert == NULL || server_key == NULL || !pcb) {
        return -1;
    }

    if (_ssl_key_password) { free((void*)_ssl_key_password); _ssl_key_password = NULL; }
    _ssl_key_password = password ? strdup(password) : NULL;

    async_tcp_log_v("Seeding the random number generator (server)");

    async_tcp_log_v("Setting up the SSL/TLS structure (server)...");

    if ((ret = mbedtls_ssl_config_defaults(&ssl_conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        return handle_error(ret);
    }

    // Force TLS 1.2 only
    mbedtls_ssl_conf_min_tls_version(&ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);

    // Disable renegotiation (only available if MBEDTLS_SSL_RENEGOTIATION is enabled)
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation(&ssl_conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif

    // Pin fast cipher suite — hardware-accelerated AES-GCM + SHA256 on ESP32
    static const int server_ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        0
    };
    mbedtls_ssl_conf_ciphersuites(&ssl_conf, server_ciphersuites);

    // Self-signed cert — no client certificate verification
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_NONE);

    // Load server certificate
    mbedtls_x509_crt_init(&client_cert);

    if (server_cert_len >= 11 && memcmp(server_cert, "-----BEGIN ", 11) == 0) {
        // PEM — make a NUL-terminated copy (mbedtls_pem_read_buffer requires it)
        async_tcp_log_v("Parsing cert PEM (%u bytes)", (unsigned)server_cert_len);
        char *pem_buf = (char *)malloc(server_cert_len + 1);
        if (!pem_buf) {
            _deleteHandshakeCerts();
            return handle_error(MBEDTLS_ERR_SSL_ALLOC_FAILED);
        }
        memcpy(pem_buf, server_cert, server_cert_len);
        pem_buf[server_cert_len] = '\0';
        mbedtls_pem_context pem;
        mbedtls_pem_init(&pem);
        size_t use_len = 0;
        size_t cert_der_len = 0;
        ret = mbedtls_pem_read_buffer(&pem,
            "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----",
            (const unsigned char *)pem_buf, NULL, 0, &use_len);
        if (ret == 0) {
            const unsigned char *der_buf = mbedtls_pem_get_buffer(&pem, &cert_der_len);
            ret = mbedtls_x509_crt_parse(&client_cert, der_buf, cert_der_len);
        }
        mbedtls_pem_free(&pem);
        free(pem_buf);
    } else {
        // DER — parse directly with length
        async_tcp_log_v("Parsing cert DER (%u bytes)", (unsigned)server_cert_len);
        ret = mbedtls_x509_crt_parse(&client_cert, server_cert, server_cert_len);
    }
    _have_client_cert = true;
    if (ret < 0) {
        _deleteHandshakeCerts();
        return handle_error(ret);
    }

    // Load server private key
    mbedtls_pk_init(&client_key);

    if (server_key_len >= 11 && memcmp(server_key, "-----BEGIN ", 11) == 0) {
        // PEM — make a NUL-terminated copy
        async_tcp_log_v("Parsing key PEM (%u bytes)", (unsigned)server_key_len);
        char *pem_buf = (char *)malloc(server_key_len + 1);
        if (!pem_buf) {
            _deleteHandshakeCerts();
            return handle_error(MBEDTLS_ERR_SSL_ALLOC_FAILED);
        }
        memcpy(pem_buf, server_key, server_key_len);
        pem_buf[server_key_len] = '\0';
        mbedtls_pem_context pem;
        mbedtls_pem_init(&pem);
        size_t use_len = 0;
        size_t key_der_len = 0;
        const unsigned char *pwd = (const unsigned char *)_ssl_key_password;
        size_t pwd_len = _ssl_key_password ? strlen(_ssl_key_password) : 0;

        const char *key_header, *key_footer;
        if (strncmp(pem_buf, "-----BEGIN ENCRYPTED PRIVATE KEY-----", 37) == 0) {
            key_header = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
            key_footer = "-----END ENCRYPTED PRIVATE KEY-----";
        } else if (strncmp(pem_buf, "-----BEGIN PRIVATE KEY-----", 27) == 0) {
            key_header = "-----BEGIN PRIVATE KEY-----";
            key_footer = "-----END PRIVATE KEY-----";
        } else {
            key_header = "-----BEGIN RSA PRIVATE KEY-----";
            key_footer = "-----END RSA PRIVATE KEY-----";
        }
        ret = mbedtls_pem_read_buffer(&pem, key_header, key_footer,
            (const unsigned char *)pem_buf, pwd, pwd_len, &use_len);
        if (ret == 0) {
            const unsigned char *der_buf = mbedtls_pem_get_buffer(&pem, &key_der_len);
            ret = _parse_private_key(&client_key, der_buf, key_der_len,
                pwd, pwd_len);
        }
        mbedtls_pem_free(&pem);
        free(pem_buf);
    } else {
        // DER — parse directly with length
        async_tcp_log_v("Parsing key DER (%u bytes)", (unsigned)server_key_len);
        ret = _parse_private_key(&client_key, server_key, server_key_len,
            NULL, 0);
    }
    _have_client_key = true;
    if (ret != 0) {
        _deleteHandshakeCerts();
        return handle_error(ret);
    }

    mbedtls_ssl_conf_own_cert(&ssl_conf, &client_cert, &client_key);

#if ASYNCTCP_MBEDTLS_MAJOR < 4
    mbedtls_ssl_conf_rng(&ssl_conf, mbedtls_ctr_drbg_random, &drbg_ctx);
#endif

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    mbedtls_ssl_conf_max_frag_len(&ssl_conf, MBEDTLS_SSL_MAX_FRAG_LEN_4096);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl_ctx, &ssl_conf)) != 0) {
        _deleteHandshakeCerts();
        return handle_error(ret);
    }

    _pcb = pcb;
    mbedtls_ssl_set_bio(&ssl_ctx, this, _lwip_ssl_send, _lwip_ssl_recv, NULL);
    handshake_start_time = 0;
    handshake_timeout = SSL_HANDSHAKE_TIMEOUT;

    return 0;
}

int AsyncTCPTLS::runSSLHandshake(void) {
    int ret, flags;

    if (!_pcb) return -1;

    if (handshake_start_time == 0) handshake_start_time = millis();
    ret = mbedtls_ssl_handshake(&ssl_ctx);
    if (ret != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return handle_error(ret);
        }
        if ((millis() - handshake_start_time) > handshake_timeout)
            return -1;
        return ret;
    }

    async_tcp_log_d("TLS handshake done: %s / %s",
        mbedtls_ssl_get_version(&ssl_ctx), mbedtls_ssl_get_ciphersuite(&ssl_ctx));

    async_tcp_log_v("Verifying peer X.509 certificate...");

    flags = mbedtls_ssl_get_verify_result(&ssl_ctx);
    if (flags != 0) {
        char buf[512];
        memset(buf, 0, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        if (strstr(buf, "skipped") != NULL) {
            async_tcp_log_v("Certificate verification was skipped (expected for self-signed server): %s", buf);
        } else {
            async_tcp_log_e("Failed to verify peer certificate! verification info: %s", buf);
            return handle_error(-1);
        }
    } else {
        async_tcp_log_v("Certificate verified.");
    }

    async_tcp_log_v("Free internal heap after TLS %u", ESP.getFreeHeap());

    return 0;
}

int AsyncTCPTLS::write(const uint8_t *data, size_t len) {
    if (!_pcb) return -1;

    int ret = mbedtls_ssl_write(&ssl_ctx, data, len);
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
        return handle_error(ret);
    }
    return ret;
}

int AsyncTCPTLS::read(uint8_t *data, size_t len) {
    if (!_ssl_rx_buf || _ssl_rx_pos >= _ssl_rx_buf_len) return 0;
    size_t avail = _ssl_rx_buf_len - _ssl_rx_pos;
    size_t copy = (avail < len) ? avail : len;
    memcpy(data, _ssl_rx_buf + _ssl_rx_pos, copy);
    _ssl_rx_pos += copy;
    // Reset buffer when all consumed (TCP ack already done in _recv)
    if (_ssl_rx_pos >= _ssl_rx_buf_len) {
        _ssl_rx_buf_len = 0;
        _ssl_rx_pos = 0;
    }
    return (int)copy;
}

int AsyncTCPTLS::sslRead(uint8_t *data, size_t len) {
    if (!_pcb) return -1;
    int ret = mbedtls_ssl_read(&ssl_ctx, data, len);
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0;
    }
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        async_tcp_log_i("SSL peer close notify");
        return 0;
    }
    if (ret == MBEDTLS_ERR_SSL_CONN_EOF) {
        return 0;
    }
    if (ret < 0) {
        async_tcp_log_e("mbedtls_ssl_read failed: -0x%04x", -ret);
        logBioState("sslRead");
        return -1;
    }
    return ret;
}

void AsyncTCPTLS::logBioState(const char *tag) const {
    async_tcp_log_e("%s: rx_buf=%u/%u pos=%u rxBufLen=%u bytes_avail=%d",
        tag, (unsigned)_ssl_rx_buf_len, (unsigned)_ssl_rx_buf_capacity,
        (unsigned)_ssl_rx_pos, (unsigned)(_ssl_rx_buf_len - _ssl_rx_pos),
        (int)mbedtls_ssl_get_bytes_avail((mbedtls_ssl_context *)&ssl_ctx));
}

void AsyncTCPTLS::sendCloseNotify(void) {
    if (!_pcb) return;
    int ret = mbedtls_ssl_close_notify(&ssl_ctx);
    if (ret != 0) {
        async_tcp_log_d("close_notify: %d", ret);
    }
}

void AsyncTCPTLS::_deleteHandshakeCerts(void) {
    if (_have_ca_cert) {
        async_tcp_log_v("Cleaning CA certificate.");
        mbedtls_ssl_conf_ca_chain(&ssl_conf, NULL, NULL);
        mbedtls_x509_crt_free(&ca_cert);
        _have_ca_cert = false;
    }
    if (_have_client_cert) {
        async_tcp_log_v("Cleaning client certificate.");
        mbedtls_ssl_conf_own_cert(&ssl_conf, NULL, NULL);
        mbedtls_x509_crt_free(&client_cert);
        _have_client_cert = false;
    }
    if (_have_client_key) {
        async_tcp_log_v("Cleaning client certificate key.");
        mbedtls_pk_free(&client_key);
        _have_client_key = false;
    }
}

#endif // ASYNC_TCP_SSL_ENABLED
