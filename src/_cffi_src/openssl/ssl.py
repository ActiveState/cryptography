# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
INCLUDES = '\n\n#include <openssl/ssl.h>\n\n\n\ntypedef STACK_OF(SSL_CIPHER) Cryptography_STACK_OF_SSL_CIPHER;\n\n'
TYPES = '\n\nstatic const long Cryptography_HAS_SSL_ST;\n\nstatic const long Cryptography_HAS_TLS_ST;\n\nstatic const long Cryptography_HAS_SSL3_METHOD;\n\nstatic const long Cryptography_HAS_TLSv1_1;\n\nstatic const long Cryptography_HAS_TLSv1_2;\n\nstatic const long Cryptography_HAS_TLSv1_3;\n\nstatic const long Cryptography_HAS_SECURE_RENEGOTIATION;\n\nstatic const long Cryptography_HAS_SSL_CTX_CLEAR_OPTIONS;\n\nstatic const long Cryptography_HAS_DTLS;\n\nstatic const long Cryptography_HAS_SIGALGS;\n\nstatic const long Cryptography_HAS_PSK;\n\nstatic const long Cryptography_HAS_VERIFIED_CHAIN;\n\nstatic const long Cryptography_HAS_KEYLOG;\n\nstatic const long Cryptography_HAS_GET_PROTO_VERSION;\n\nstatic const long Cryptography_HAS_TLSEXT_HOSTNAME;\n\n\n\n/* Internally invented symbol to tell us if SSL_MODE_RELEASE_BUFFERS is\n\n * supported\n\n */\n\nstatic const long Cryptography_HAS_RELEASE_BUFFERS;\n\n\n\n/* Internally invented symbol to tell us if SSL_OP_NO_COMPRESSION is\n\n * supported\n\n */\n\nstatic const long Cryptography_HAS_OP_NO_COMPRESSION;\n\nstatic const long Cryptography_HAS_OP_NO_RENEGOTIATION;\n\nstatic const long Cryptography_HAS_SSL_OP_MSIE_SSLV2_RSA_PADDING;\n\nstatic const long Cryptography_HAS_SSL_SET_SSL_CTX;\n\nstatic const long Cryptography_HAS_SSL_OP_NO_TICKET;\n\nstatic const long Cryptography_HAS_ALPN;\n\nstatic const long Cryptography_HAS_NEXTPROTONEG;\n\nstatic const long Cryptography_HAS_SET_CERT_CB;\n\nstatic const long Cryptography_HAS_CUSTOM_EXT;\n\nstatic const long Cryptography_HAS_SRTP;\n\nstatic const long Cryptography_HAS_DTLS_GET_DATA_MTU;\n\n\n\nstatic const long SSL_FILETYPE_PEM;\n\nstatic const long SSL_FILETYPE_ASN1;\n\nstatic const long SSL_ERROR_NONE;\n\nstatic const long SSL_ERROR_ZERO_RETURN;\n\nstatic const long SSL_ERROR_WANT_READ;\n\nstatic const long SSL_ERROR_WANT_WRITE;\n\nstatic const long SSL_ERROR_WANT_X509_LOOKUP;\n\nstatic const long SSL_ERROR_WANT_CONNECT;\n\nstatic const long SSL_ERROR_SYSCALL;\n\nstatic const long SSL_ERROR_SSL;\n\nstatic const long SSL_SENT_SHUTDOWN;\n\nstatic const long SSL_RECEIVED_SHUTDOWN;\n\nstatic const long SSL_OP_NO_SSLv2;\n\nstatic const long SSL_OP_NO_SSLv3;\n\nstatic const long SSL_OP_NO_TLSv1;\n\nstatic const long SSL_OP_NO_TLSv1_1;\n\nstatic const long SSL_OP_NO_TLSv1_2;\n\nstatic const long SSL_OP_NO_TLSv1_3;\n\nstatic const long SSL_OP_NO_DTLSv1;\n\nstatic const long SSL_OP_NO_DTLSv1_2;\n\nstatic const long SSL_OP_NO_RENEGOTIATION;\n\nstatic const long SSL_OP_NO_COMPRESSION;\n\nstatic const long SSL_OP_SINGLE_DH_USE;\n\nstatic const long SSL_OP_EPHEMERAL_RSA;\n\nstatic const long SSL_OP_MICROSOFT_SESS_ID_BUG;\n\nstatic const long SSL_OP_NETSCAPE_CHALLENGE_BUG;\n\nstatic const long SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;\n\nstatic const long SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG;\n\nstatic const long SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER;\n\nstatic const long SSL_OP_MSIE_SSLV2_RSA_PADDING;\n\nstatic const long SSL_OP_SSLEAY_080_CLIENT_DH_BUG;\n\nstatic const long SSL_OP_TLS_D5_BUG;\n\nstatic const long SSL_OP_TLS_BLOCK_PADDING_BUG;\n\nstatic const long SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;\n\nstatic const long SSL_OP_CIPHER_SERVER_PREFERENCE;\n\nstatic const long SSL_OP_TLS_ROLLBACK_BUG;\n\nstatic const long SSL_OP_PKCS1_CHECK_1;\n\nstatic const long SSL_OP_PKCS1_CHECK_2;\n\nstatic const long SSL_OP_NETSCAPE_CA_DN_BUG;\n\nstatic const long SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG;\n\nstatic const long SSL_OP_NO_QUERY_MTU;\n\nstatic const long SSL_OP_COOKIE_EXCHANGE;\n\nstatic const long SSL_OP_NO_TICKET;\n\nstatic const long SSL_OP_ALL;\n\nstatic const long SSL_OP_SINGLE_ECDH_USE;\n\nstatic const long SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;\n\nstatic const long SSL_OP_LEGACY_SERVER_CONNECT;\n\nstatic const long SSL_VERIFY_PEER;\n\nstatic const long SSL_VERIFY_FAIL_IF_NO_PEER_CERT;\n\nstatic const long SSL_VERIFY_CLIENT_ONCE;\n\nstatic const long SSL_VERIFY_NONE;\n\nstatic const long SSL_VERIFY_POST_HANDSHAKE;\n\nstatic const long SSL_SESS_CACHE_OFF;\n\nstatic const long SSL_SESS_CACHE_CLIENT;\n\nstatic const long SSL_SESS_CACHE_SERVER;\n\nstatic const long SSL_SESS_CACHE_BOTH;\n\nstatic const long SSL_SESS_CACHE_NO_AUTO_CLEAR;\n\nstatic const long SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;\n\nstatic const long SSL_SESS_CACHE_NO_INTERNAL_STORE;\n\nstatic const long SSL_SESS_CACHE_NO_INTERNAL;\n\nstatic const long SSL_ST_CONNECT;\n\nstatic const long SSL_ST_ACCEPT;\n\nstatic const long SSL_ST_MASK;\n\nstatic const long SSL_ST_INIT;\n\nstatic const long SSL_ST_BEFORE;\n\nstatic const long SSL_ST_OK;\n\nstatic const long SSL_ST_RENEGOTIATE;\n\nstatic const long SSL_CB_LOOP;\n\nstatic const long SSL_CB_EXIT;\n\nstatic const long SSL_CB_READ;\n\nstatic const long SSL_CB_WRITE;\n\nstatic const long SSL_CB_ALERT;\n\nstatic const long SSL_CB_READ_ALERT;\n\nstatic const long SSL_CB_WRITE_ALERT;\n\nstatic const long SSL_CB_ACCEPT_LOOP;\n\nstatic const long SSL_CB_ACCEPT_EXIT;\n\nstatic const long SSL_CB_CONNECT_LOOP;\n\nstatic const long SSL_CB_CONNECT_EXIT;\n\nstatic const long SSL_CB_HANDSHAKE_START;\n\nstatic const long SSL_CB_HANDSHAKE_DONE;\n\nstatic const long SSL_MODE_RELEASE_BUFFERS;\n\nstatic const long SSL_MODE_ENABLE_PARTIAL_WRITE;\n\nstatic const long SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;\n\nstatic const long SSL_MODE_AUTO_RETRY;\n\nstatic const long SSL3_RANDOM_SIZE;\n\nstatic const long TLS_ST_BEFORE;\n\nstatic const long TLS_ST_OK;\n\n\n\nstatic const long SSL3_VERSION;\n\nstatic const long TLS1_VERSION;\n\nstatic const long TLS1_1_VERSION;\n\nstatic const long TLS1_2_VERSION;\n\nstatic const long TLS1_3_VERSION;\n\n\n\ntypedef ... SSL_METHOD;\n\ntypedef ... SSL_CTX;\n\n\n\ntypedef ... SSL_SESSION;\n\n\n\ntypedef ... SSL;\n\n\n\nstatic const long TLSEXT_NAMETYPE_host_name;\n\nstatic const long TLSEXT_STATUSTYPE_ocsp;\n\n\n\ntypedef ... SSL_CIPHER;\n\ntypedef ... Cryptography_STACK_OF_SSL_CIPHER;\n\n\n\ntypedef struct {\n\n    const char *name;\n\n    unsigned long id;\n\n} SRTP_PROTECTION_PROFILE;\n\n'
FUNCTIONS = "\n\n/*  SSL */\n\nconst char *SSL_state_string_long(const SSL *);\n\nSSL_SESSION *SSL_get1_session(SSL *);\n\nint SSL_set_session(SSL *, SSL_SESSION *);\n\nSSL *SSL_new(SSL_CTX *);\n\nvoid SSL_free(SSL *);\n\nint SSL_set_fd(SSL *, int);\n\nSSL_CTX *SSL_set_SSL_CTX(SSL *, SSL_CTX *);\n\nvoid SSL_set_bio(SSL *, BIO *, BIO *);\n\nvoid SSL_set_connect_state(SSL *);\n\nvoid SSL_set_accept_state(SSL *);\n\nvoid SSL_set_shutdown(SSL *, int);\n\nint SSL_get_shutdown(const SSL *);\n\nint SSL_pending(const SSL *);\n\nint SSL_write(SSL *, const void *, int);\n\nint SSL_read(SSL *, void *, int);\n\nint SSL_peek(SSL *, void *, int);\n\nX509 *SSL_get_certificate(const SSL *);\n\nX509 *SSL_get_peer_certificate(const SSL *);\n\nint SSL_get_ex_data_X509_STORE_CTX_idx(void);\n\n\n\n/* Added in 1.0.2 */\n\nX509_VERIFY_PARAM *SSL_get0_param(SSL *);\n\nX509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *);\n\n\n\nint SSL_get_sigalgs(SSL *, int, int *, int *, int *, unsigned char *,\n\n                    unsigned char *);\n\n\n\nCryptography_STACK_OF_X509 *SSL_get_peer_cert_chain(const SSL *);\n\nCryptography_STACK_OF_X509 *SSL_get0_verified_chain(const SSL *);\n\nCryptography_STACK_OF_X509_NAME *SSL_get_client_CA_list(const SSL *);\n\n\n\nint SSL_get_error(const SSL *, int);\n\nlong SSL_get_verify_result(const SSL *ssl);\n\nint SSL_do_handshake(SSL *);\n\nint SSL_shutdown(SSL *);\n\nint SSL_renegotiate(SSL *);\n\nint SSL_renegotiate_pending(SSL *);\n\nconst char *SSL_get_cipher_list(const SSL *, int);\n\n\n\n/*  context */\n\nvoid SSL_CTX_free(SSL_CTX *);\n\nlong SSL_CTX_set_timeout(SSL_CTX *, long);\n\nint SSL_CTX_set_default_verify_paths(SSL_CTX *);\n\nvoid SSL_CTX_set_verify(SSL_CTX *, int, int (*)(int, X509_STORE_CTX *));\n\nvoid SSL_CTX_set_verify_depth(SSL_CTX *, int);\n\nint SSL_CTX_get_verify_mode(const SSL_CTX *);\n\nint SSL_CTX_get_verify_depth(const SSL_CTX *);\n\nint SSL_CTX_set_cipher_list(SSL_CTX *, const char *);\n\nint SSL_CTX_load_verify_locations(SSL_CTX *, const char *, const char *);\n\nvoid SSL_CTX_set_default_passwd_cb(SSL_CTX *, pem_password_cb *);\n\nvoid SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *, void *);\n\nint SSL_CTX_use_certificate(SSL_CTX *, X509 *);\n\nint SSL_CTX_use_certificate_file(SSL_CTX *, const char *, int);\n\nint SSL_CTX_use_certificate_chain_file(SSL_CTX *, const char *);\n\nint SSL_CTX_use_PrivateKey(SSL_CTX *, EVP_PKEY *);\n\nint SSL_CTX_use_PrivateKey_file(SSL_CTX *, const char *, int);\n\nint SSL_CTX_check_private_key(const SSL_CTX *);\n\nvoid SSL_CTX_set_cert_verify_callback(SSL_CTX *,\n\n                                      int (*)(X509_STORE_CTX *, void *),\n\n                                      void *);\n\n\n\nvoid SSL_CTX_set_cookie_generate_cb(SSL_CTX *,\n\n                                    int (*)(\n\n                                        SSL *,\n\n                                        unsigned char *,\n\n                                        unsigned int *\n\n                                    ));\n\nvoid SSL_CTX_set_cookie_verify_cb(SSL_CTX *,\n\n                                    int (*)(\n\n                                        SSL *,\n\n                                        const unsigned char *,\n\n                                        unsigned int\n\n                                    ));\n\n\n\nlong SSL_CTX_get_read_ahead(SSL_CTX *);\n\nlong SSL_CTX_set_read_ahead(SSL_CTX *, long);\n\n\n\nint SSL_CTX_use_psk_identity_hint(SSL_CTX *, const char *);\n\nvoid SSL_CTX_set_psk_server_callback(SSL_CTX *,\n\n                                     unsigned int (*)(\n\n                                         SSL *,\n\n                                         const char *,\n\n                                         unsigned char *,\n\n                                         unsigned int\n\n                                     ));\n\nvoid SSL_CTX_set_psk_client_callback(SSL_CTX *,\n\n                                     unsigned int (*)(\n\n                                         SSL *,\n\n                                         const char *,\n\n                                         char *,\n\n                                         unsigned int,\n\n                                         unsigned char *,\n\n                                         unsigned int\n\n                                     ));\n\n\n\nint SSL_CTX_set_session_id_context(SSL_CTX *, const unsigned char *,\n\n                                   unsigned int);\n\n\n\nvoid SSL_CTX_set_cert_store(SSL_CTX *, X509_STORE *);\n\nX509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *);\n\nint SSL_CTX_add_client_CA(SSL_CTX *, X509 *);\n\n\n\nvoid SSL_CTX_set_client_CA_list(SSL_CTX *, Cryptography_STACK_OF_X509_NAME *);\n\n\n\nvoid SSL_CTX_set_info_callback(SSL_CTX *, void (*)(const SSL *, int, int));\n\nvoid (*SSL_CTX_get_info_callback(SSL_CTX *))(const SSL *, int, int);\n\n\n\nvoid SSL_CTX_set_keylog_callback(SSL_CTX *,\n\n                                 void (*)(const SSL *, const char *));\n\nvoid (*SSL_CTX_get_keylog_callback(SSL_CTX *))(const SSL *, const char *);\n\n\n\nlong SSL_CTX_set1_sigalgs_list(SSL_CTX *, const char *);\n\n\n\n/*  SSL_SESSION */\n\nvoid SSL_SESSION_free(SSL_SESSION *);\n\n\n\n/* Information about actually used cipher */\n\nconst char *SSL_CIPHER_get_name(const SSL_CIPHER *);\n\nint SSL_CIPHER_get_bits(const SSL_CIPHER *, int *);\n\n/* the modern signature of this is uint32_t, but older openssl declared it\n\n   as unsigned long. To make our compiler flags happy we'll declare it as a\n\n   64-bit wide value, which should always be safe */\n\nuint64_t SSL_CIPHER_get_id(const SSL_CIPHER *);\n\nint SSL_CIPHER_is_aead(const SSL_CIPHER *);\n\nint SSL_CIPHER_get_cipher_nid(const SSL_CIPHER *);\n\nint SSL_CIPHER_get_digest_nid(const SSL_CIPHER *);\n\nint SSL_CIPHER_get_kx_nid(const SSL_CIPHER *);\n\nint SSL_CIPHER_get_auth_nid(const SSL_CIPHER *);\n\n\n\nsize_t SSL_get_finished(const SSL *, void *, size_t);\n\nsize_t SSL_get_peer_finished(const SSL *, void *, size_t);\n\nCryptography_STACK_OF_X509_NAME *SSL_load_client_CA_file(const char *);\n\n\n\nconst char *SSL_get_servername(const SSL *, const int);\n\n/* Function signature changed to const char * in 1.1.0 */\n\nconst char *SSL_CIPHER_get_version(const SSL_CIPHER *);\n\n/* These became macros in 1.1.0 */\n\nint SSL_library_init(void);\n\nvoid SSL_load_error_strings(void);\n\n\n\n/* these CRYPTO_EX_DATA functions became macros in 1.1.0 */\n\nint SSL_get_ex_new_index(long, void *, CRYPTO_EX_new *, CRYPTO_EX_dup *,\n\n                         CRYPTO_EX_free *);\n\nint SSL_set_ex_data(SSL *, int, void *);\n\nint SSL_CTX_get_ex_new_index(long, void *, CRYPTO_EX_new *, CRYPTO_EX_dup *,\n\n                             CRYPTO_EX_free *);\n\nint SSL_CTX_set_ex_data(SSL_CTX *, int, void *);\n\n\n\nSSL_SESSION *SSL_get_session(const SSL *);\n\nconst unsigned char *SSL_SESSION_get_id(const SSL_SESSION *, unsigned int *);\n\nlong SSL_SESSION_get_time(const SSL_SESSION *);\n\nlong SSL_SESSION_get_timeout(const SSL_SESSION *);\n\nint SSL_SESSION_has_ticket(const SSL_SESSION *);\n\nlong SSL_SESSION_get_ticket_lifetime_hint(const SSL_SESSION *);\n\n\n\nunsigned long SSL_set_mode(SSL *, unsigned long);\n\nunsigned long SSL_clear_mode(SSL *, unsigned long);\n\nunsigned long SSL_get_mode(SSL *);\n\n\n\nunsigned long SSL_set_options(SSL *, unsigned long);\n\nunsigned long SSL_get_options(SSL *);\n\n\n\nint SSL_want_read(const SSL *);\n\nint SSL_want_write(const SSL *);\n\n\n\nlong SSL_total_renegotiations(SSL *);\n\nlong SSL_get_secure_renegotiation_support(SSL *);\n\n\n\nlong SSL_CTX_set_min_proto_version(SSL_CTX *, int);\n\nlong SSL_CTX_set_max_proto_version(SSL_CTX *, int);\n\nlong SSL_set_min_proto_version(SSL *, int);\n\nlong SSL_set_max_proto_version(SSL *, int);\n\n\n\nlong SSL_CTX_get_min_proto_version(SSL_CTX *);\n\nlong SSL_CTX_get_max_proto_version(SSL_CTX *);\n\nlong SSL_get_min_proto_version(SSL *);\n\nlong SSL_get_max_proto_version(SSL *);\n\n\n\n/* Defined as unsigned long because SSL_OP_ALL is greater than signed 32-bit\n\n   and Windows defines long as 32-bit. */\n\nunsigned long SSL_CTX_set_options(SSL_CTX *, unsigned long);\n\nunsigned long SSL_CTX_clear_options(SSL_CTX *, unsigned long);\n\nunsigned long SSL_CTX_get_options(SSL_CTX *);\n\nunsigned long SSL_CTX_set_mode(SSL_CTX *, unsigned long);\n\nunsigned long SSL_CTX_clear_mode(SSL_CTX *, unsigned long);\n\nunsigned long SSL_CTX_get_mode(SSL_CTX *);\n\nunsigned long SSL_CTX_set_session_cache_mode(SSL_CTX *, unsigned long);\n\nunsigned long SSL_CTX_get_session_cache_mode(SSL_CTX *);\n\nunsigned long SSL_CTX_set_tmp_dh(SSL_CTX *, DH *);\n\nunsigned long SSL_CTX_set_tmp_ecdh(SSL_CTX *, EC_KEY *);\n\nunsigned long SSL_CTX_add_extra_chain_cert(SSL_CTX *, X509 *);\n\n\n\n/*- These aren't macros these functions are all const X on openssl > 1.0.x -*/\n\n\n\n/*  methods */\n\n\n\nconst SSL_METHOD *TLSv1_1_method(void);\n\nconst SSL_METHOD *TLSv1_1_server_method(void);\n\nconst SSL_METHOD *TLSv1_1_client_method(void);\n\n\n\nconst SSL_METHOD *TLSv1_2_method(void);\n\nconst SSL_METHOD *TLSv1_2_server_method(void);\n\nconst SSL_METHOD *TLSv1_2_client_method(void);\n\n\n\nconst SSL_METHOD *SSLv3_method(void);\n\nconst SSL_METHOD *SSLv3_server_method(void);\n\nconst SSL_METHOD *SSLv3_client_method(void);\n\n\n\nconst SSL_METHOD *TLSv1_method(void);\n\nconst SSL_METHOD *TLSv1_server_method(void);\n\nconst SSL_METHOD *TLSv1_client_method(void);\n\n\n\nconst SSL_METHOD *DTLSv1_method(void);\n\nconst SSL_METHOD *DTLSv1_server_method(void);\n\nconst SSL_METHOD *DTLSv1_client_method(void);\n\n\n\n/* Added in 1.0.2 */\n\nconst SSL_METHOD *DTLS_method(void);\n\nconst SSL_METHOD *DTLS_server_method(void);\n\nconst SSL_METHOD *DTLS_client_method(void);\n\n\n\nconst SSL_METHOD *SSLv23_method(void);\n\nconst SSL_METHOD *SSLv23_server_method(void);\n\nconst SSL_METHOD *SSLv23_client_method(void);\n\n\n\nconst SSL_METHOD *TLS_method(void);\n\nconst SSL_METHOD *TLS_server_method(void);\n\nconst SSL_METHOD *TLS_client_method(void);\n\n\n\n/*- These aren't macros these arguments are all const X on openssl > 1.0.x -*/\n\nSSL_CTX *SSL_CTX_new(SSL_METHOD *);\n\nlong SSL_CTX_get_timeout(const SSL_CTX *);\n\n\n\nconst SSL_CIPHER *SSL_get_current_cipher(const SSL *);\n\nconst char *SSL_get_version(const SSL *);\n\nint SSL_version(const SSL *);\n\n\n\nvoid *SSL_CTX_get_ex_data(const SSL_CTX *, int);\n\nvoid *SSL_get_ex_data(const SSL *, int);\n\n\n\nvoid SSL_set_tlsext_host_name(SSL *, char *);\n\nvoid SSL_CTX_set_tlsext_servername_callback(\n\n    SSL_CTX *,\n\n    int (*)(SSL *, int *, void *));\n\nvoid SSL_CTX_set_tlsext_servername_arg(\n\n    SSL_CTX *, void *);\n\n\n\nlong SSL_set_tlsext_status_ocsp_resp(SSL *, unsigned char *, int);\n\nlong SSL_get_tlsext_status_ocsp_resp(SSL *, const unsigned char **);\n\nlong SSL_set_tlsext_status_type(SSL *, long);\n\nlong SSL_CTX_set_tlsext_status_cb(SSL_CTX *, int(*)(SSL *, void *));\n\nlong SSL_CTX_set_tlsext_status_arg(SSL_CTX *, void *);\n\n\n\nint SSL_CTX_set_tlsext_use_srtp(SSL_CTX *, const char *);\n\nint SSL_set_tlsext_use_srtp(SSL *, const char *);\n\nSRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *);\n\n\n\nlong SSL_session_reused(SSL *);\n\n\n\nint SSL_select_next_proto(unsigned char **, unsigned char *,\n\n                          const unsigned char *, unsigned int,\n\n                          const unsigned char *, unsigned int);\n\n\n\nint sk_SSL_CIPHER_num(Cryptography_STACK_OF_SSL_CIPHER *);\n\nconst SSL_CIPHER *sk_SSL_CIPHER_value(Cryptography_STACK_OF_SSL_CIPHER *, int);\n\n\n\n/* ALPN APIs were introduced in OpenSSL 1.0.2.  To continue to support earlier\n\n * versions some special handling of these is necessary.\n\n */\n\nint SSL_CTX_set_alpn_protos(SSL_CTX *, const unsigned char *, unsigned);\n\nint SSL_set_alpn_protos(SSL *, const unsigned char *, unsigned);\n\nvoid SSL_CTX_set_alpn_select_cb(SSL_CTX *,\n\n                                int (*) (SSL *,\n\n                                         const unsigned char **,\n\n                                         unsigned char *,\n\n                                         const unsigned char *,\n\n                                         unsigned int,\n\n                                         void *),\n\n                                void *);\n\nvoid SSL_get0_alpn_selected(const SSL *, const unsigned char **, unsigned *);\n\n\n\nlong SSL_get_server_tmp_key(SSL *, EVP_PKEY **);\n\n\n\n/* SSL_CTX_set_cert_cb is introduced in OpenSSL 1.0.2. To continue to support\n\n * earlier versions some special handling of these is necessary.\n\n */\n\nvoid SSL_CTX_set_cert_cb(SSL_CTX *, int (*)(SSL *, void *), void *);\n\nvoid SSL_set_cert_cb(SSL *, int (*)(SSL *, void *), void *);\n\n\n\nint SSL_SESSION_set1_id_context(SSL_SESSION *, const unsigned char *,\n\n                                unsigned int);\n\n/* Added in 1.1.0 for the great opaquing of structs */\n\nsize_t SSL_SESSION_get_master_key(const SSL_SESSION *, unsigned char *,\n\n                                  size_t);\n\nsize_t SSL_get_client_random(const SSL *, unsigned char *, size_t);\n\nsize_t SSL_get_server_random(const SSL *, unsigned char *, size_t);\n\nint SSL_export_keying_material(SSL *, unsigned char *, size_t, const char *,\n\n                               size_t, const unsigned char *, size_t, int);\n\n\n\nlong SSL_CTX_sess_number(SSL_CTX *);\n\nlong SSL_CTX_sess_connect(SSL_CTX *);\n\nlong SSL_CTX_sess_connect_good(SSL_CTX *);\n\nlong SSL_CTX_sess_connect_renegotiate(SSL_CTX *);\n\nlong SSL_CTX_sess_accept(SSL_CTX *);\n\nlong SSL_CTX_sess_accept_good(SSL_CTX *);\n\nlong SSL_CTX_sess_accept_renegotiate(SSL_CTX *);\n\nlong SSL_CTX_sess_hits(SSL_CTX *);\n\nlong SSL_CTX_sess_cb_hits(SSL_CTX *);\n\nlong SSL_CTX_sess_misses(SSL_CTX *);\n\nlong SSL_CTX_sess_timeouts(SSL_CTX *);\n\nlong SSL_CTX_sess_cache_full(SSL_CTX *);\n\n\n\n/* DTLS support */\n\nlong Cryptography_DTLSv1_get_timeout(SSL *, time_t *, long *);\n\nlong DTLSv1_handle_timeout(SSL *);\n\nlong DTLS_set_link_mtu(SSL *, long);\n\nlong DTLS_get_link_min_mtu(SSL *);\n\nlong SSL_set_mtu(SSL *, long);\n\nint DTLSv1_listen(SSL *, BIO_ADDR *);\n\nsize_t DTLS_get_data_mtu(SSL *);\n\n\n\n\n\n/* Custom extensions. */\n\ntypedef int (*custom_ext_add_cb)(SSL *, unsigned int,\n\n                                 const unsigned char **,\n\n                                 size_t *, int *,\n\n                                 void *);\n\n\n\ntypedef void (*custom_ext_free_cb)(SSL *, unsigned int,\n\n                                   const unsigned char *,\n\n                                   void *);\n\n\n\ntypedef int (*custom_ext_parse_cb)(SSL *, unsigned int,\n\n                                   const unsigned char *,\n\n                                   size_t, int *,\n\n                                   void *);\n\n\n\nint SSL_CTX_add_client_custom_ext(SSL_CTX *, unsigned int,\n\n                                  custom_ext_add_cb,\n\n                                  custom_ext_free_cb, void *,\n\n                                  custom_ext_parse_cb,\n\n                                  void *);\n\n\n\nint SSL_CTX_add_server_custom_ext(SSL_CTX *, unsigned int,\n\n                                  custom_ext_add_cb,\n\n                                  custom_ext_free_cb, void *,\n\n                                  custom_ext_parse_cb,\n\n                                  void *);\n\n\n\nint SSL_extension_supported(unsigned int);\n\n\n\nint SSL_CTX_set_ciphersuites(SSL_CTX *, const char *);\n\nint SSL_verify_client_post_handshake(SSL *);\n\nvoid SSL_CTX_set_post_handshake_auth(SSL_CTX *, int);\n\nvoid SSL_set_post_handshake_auth(SSL *, int);\n\n\n\nuint32_t SSL_SESSION_get_max_early_data(const SSL_SESSION *);\n\nint SSL_write_early_data(SSL *, const void *, size_t, size_t *);\n\nint SSL_read_early_data(SSL *, void *, size_t, size_t *);\n\nint SSL_CTX_set_max_early_data(SSL_CTX *, uint32_t);\n\n"
CUSTOMIZATIONS = "\n\n// This symbol is being preserved because removing it will break users with\n\n// pyOpenSSL < 19.1 and pip < 20.x. We need to leave this in place until those\n\n// users have upgraded. PersistentlyDeprecated2020\n\nstatic const long Cryptography_HAS_TLSEXT_HOSTNAME = 1;\n\n\n\n#if CRYPTOGRAPHY_IS_LIBRESSL\n\nstatic const long Cryptography_HAS_VERIFIED_CHAIN = 0;\n\nCryptography_STACK_OF_X509 *(*SSL_get0_verified_chain)(const SSL *) = NULL;\n\n#else\n\nstatic const long Cryptography_HAS_VERIFIED_CHAIN = 1;\n\n#endif\n\n\n\n#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_111\n\nstatic const long Cryptography_HAS_KEYLOG = 0;\n\nvoid (*SSL_CTX_set_keylog_callback)(SSL_CTX *,\n\n                                    void (*) (const SSL *, const char *)\n\n                                    ) = NULL;\n\nvoid (*(*SSL_CTX_get_keylog_callback)(SSL_CTX *))(\n\n                                                  const SSL *,\n\n                                                  const char *\n\n                                                  ) = NULL;\n\n#else\n\nstatic const long Cryptography_HAS_KEYLOG = 1;\n\n#endif\n\n\n\nstatic const long Cryptography_HAS_SECURE_RENEGOTIATION = 1;\n\n\n\n#ifdef OPENSSL_NO_SSL3_METHOD\n\nstatic const long Cryptography_HAS_SSL3_METHOD = 0;\n\nSSL_METHOD* (*SSLv3_method)(void) = NULL;\n\nSSL_METHOD* (*SSLv3_client_method)(void) = NULL;\n\nSSL_METHOD* (*SSLv3_server_method)(void) = NULL;\n\n#else\n\nstatic const long Cryptography_HAS_SSL3_METHOD = 1;\n\n#endif\n\n\n\nstatic const long Cryptography_HAS_RELEASE_BUFFERS = 1;\n\nstatic const long Cryptography_HAS_OP_NO_COMPRESSION = 1;\n\nstatic const long Cryptography_HAS_TLSv1_1 = 1;\n\nstatic const long Cryptography_HAS_TLSv1_2 = 1;\n\nstatic const long Cryptography_HAS_SSL_OP_MSIE_SSLV2_RSA_PADDING = 1;\n\nstatic const long Cryptography_HAS_SSL_OP_NO_TICKET = 1;\n\nstatic const long Cryptography_HAS_SSL_SET_SSL_CTX = 1;\n\nstatic const long Cryptography_HAS_NEXTPROTONEG = 0;\n\nstatic const long Cryptography_HAS_ALPN = 1;\n\n\n\n#ifdef SSL_OP_NO_RENEGOTIATION\n\nstatic const long Cryptography_HAS_OP_NO_RENEGOTIATION = 1;\n\n#else\n\nstatic const long Cryptography_HAS_OP_NO_RENEGOTIATION = 0;\n\nstatic const long SSL_OP_NO_RENEGOTIATION = 0;\n\n#endif\n\n\n\n#if CRYPTOGRAPHY_IS_LIBRESSL\n\nvoid (*SSL_CTX_set_cert_cb)(SSL_CTX *, int (*)(SSL *, void *), void *) = NULL;\n\nvoid (*SSL_set_cert_cb)(SSL *, int (*)(SSL *, void *), void *) = NULL;\n\nstatic const long Cryptography_HAS_SET_CERT_CB = 0;\n\n#else\n\nstatic const long Cryptography_HAS_SET_CERT_CB = 1;\n\n#endif\n\n\n\nstatic const long Cryptography_HAS_SSL_CTX_CLEAR_OPTIONS = 1;\n\n\n\n/* in OpenSSL 1.1.0 the SSL_ST values were renamed to TLS_ST and several were\n\n   removed */\n\n#if CRYPTOGRAPHY_IS_LIBRESSL\n\nstatic const long Cryptography_HAS_SSL_ST = 1;\n\n#else\n\nstatic const long Cryptography_HAS_SSL_ST = 0;\n\nstatic const long SSL_ST_BEFORE = 0;\n\nstatic const long SSL_ST_OK = 0;\n\nstatic const long SSL_ST_INIT = 0;\n\nstatic const long SSL_ST_RENEGOTIATE = 0;\n\n#endif\n\n#if !CRYPTOGRAPHY_IS_LIBRESSL\n\nstatic const long Cryptography_HAS_TLS_ST = 1;\n\n#else\n\nstatic const long Cryptography_HAS_TLS_ST = 0;\n\nstatic const long TLS_ST_BEFORE = 0;\n\nstatic const long TLS_ST_OK = 0;\n\n#endif\n\n\n\n#if CRYPTOGRAPHY_IS_LIBRESSL\n\n#if CRYPTOGRAPHY_LIBRESSL_LESS_THAN_332\n\nstatic const long SSL_OP_NO_DTLSv1 = 0;\n\nstatic const long SSL_OP_NO_DTLSv1_2 = 0;\n\n#endif\n\nlong (*DTLS_set_link_mtu)(SSL *, long) = NULL;\n\nlong (*DTLS_get_link_min_mtu)(SSL *) = NULL;\n\n#endif\n\n\n\n#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_111\n\nstatic const long Cryptography_HAS_DTLS_GET_DATA_MTU = 0;\n\nsize_t (*DTLS_get_data_mtu)(SSL *) = NULL;\n\n#else\n\nstatic const long Cryptography_HAS_DTLS_GET_DATA_MTU = 1;\n\n#endif\n\n\n\nstatic const long Cryptography_HAS_DTLS = 1;\n\n/* Wrap DTLSv1_get_timeout to avoid cffi to handle a 'struct timeval'. */\n\nlong Cryptography_DTLSv1_get_timeout(SSL *ssl, time_t *ptv_sec,\n\n                                     long *ptv_usec) {\n\n    struct timeval tv = { 0 };\n\n    long r = DTLSv1_get_timeout(ssl, &tv);\n\n\n\n    if (r == 1) {\n\n        if (ptv_sec) {\n\n            *ptv_sec = tv.tv_sec;\n\n        }\n\n\n\n        if (ptv_usec) {\n\n            *ptv_usec = tv.tv_usec;\n\n        }\n\n    }\n\n\n\n    return r;\n\n}\n\n\n\n#if CRYPTOGRAPHY_IS_LIBRESSL\n\nstatic const long Cryptography_HAS_SIGALGS = 0;\n\nconst int (*SSL_get_sigalgs)(SSL *, int, int *, int *, int *, unsigned char *,\n\n                             unsigned char *) = NULL;\n\nconst long (*SSL_CTX_set1_sigalgs_list)(SSL_CTX *, const char *) = NULL;\n\n#else\n\nstatic const long Cryptography_HAS_SIGALGS = 1;\n\n#endif\n\n\n\n#if CRYPTOGRAPHY_IS_LIBRESSL || defined(OPENSSL_NO_PSK)\n\nstatic const long Cryptography_HAS_PSK = 0;\n\nint (*SSL_CTX_use_psk_identity_hint)(SSL_CTX *, const char *) = NULL;\n\nvoid (*SSL_CTX_set_psk_server_callback)(SSL_CTX *,\n\n                                        unsigned int (*)(\n\n                                            SSL *,\n\n                                            const char *,\n\n                                            unsigned char *,\n\n                                            unsigned int\n\n                                        )) = NULL;\n\nvoid (*SSL_CTX_set_psk_client_callback)(SSL_CTX *,\n\n                                        unsigned int (*)(\n\n                                            SSL *,\n\n                                            const char *,\n\n                                            char *,\n\n                                            unsigned int,\n\n                                            unsigned char *,\n\n                                            unsigned int\n\n                                        )) = NULL;\n\n#else\n\nstatic const long Cryptography_HAS_PSK = 1;\n\n#endif\n\n\n\n#if !CRYPTOGRAPHY_IS_LIBRESSL\n\nstatic const long Cryptography_HAS_CUSTOM_EXT = 1;\n\n#else\n\nstatic const long Cryptography_HAS_CUSTOM_EXT = 0;\n\ntypedef int (*custom_ext_add_cb)(SSL *, unsigned int,\n\n                                 const unsigned char **,\n\n                                 size_t *, int *,\n\n                                 void *);\n\ntypedef void (*custom_ext_free_cb)(SSL *, unsigned int,\n\n                                   const unsigned char *,\n\n                                   void *);\n\ntypedef int (*custom_ext_parse_cb)(SSL *, unsigned int,\n\n                                   const unsigned char *,\n\n                                   size_t, int *,\n\n                                   void *);\n\nint (*SSL_CTX_add_client_custom_ext)(SSL_CTX *, unsigned int,\n\n                                     custom_ext_add_cb,\n\n                                     custom_ext_free_cb, void *,\n\n                                     custom_ext_parse_cb,\n\n                                     void *) = NULL;\n\nint (*SSL_CTX_add_server_custom_ext)(SSL_CTX *, unsigned int,\n\n                                     custom_ext_add_cb,\n\n                                     custom_ext_free_cb, void *,\n\n                                     custom_ext_parse_cb,\n\n                                     void *) = NULL;\n\nint (*SSL_extension_supported)(unsigned int) = NULL;\n\n#endif\n\n\n\n#ifndef OPENSSL_NO_SRTP\n\nstatic const long Cryptography_HAS_SRTP = 1;\n\n#else\n\nstatic const long Cryptography_HAS_SRTP = 0;\n\nint (*SSL_CTX_set_tlsext_use_srtp)(SSL_CTX *, const char *) = NULL;\n\nint (*SSL_set_tlsext_use_srtp)(SSL *, const char *) = NULL;\n\nSRTP_PROTECTION_PROFILE * (*SSL_get_selected_srtp_profile)(SSL *) = NULL;\n\n#endif\n\n\n\n#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_111\n\nstatic const long Cryptography_HAS_TLSv1_3 = 0;\n\nstatic const long TLS1_3_VERSION = 0;\n\nstatic const long SSL_OP_NO_TLSv1_3 = 0;\n\nstatic const long SSL_VERIFY_POST_HANDSHAKE = 0;\n\nint (*SSL_CTX_set_ciphersuites)(SSL_CTX *, const char *) = NULL;\n\nint (*SSL_verify_client_post_handshake)(SSL *) = NULL;\n\nvoid (*SSL_CTX_set_post_handshake_auth)(SSL_CTX *, int) = NULL;\n\nvoid (*SSL_set_post_handshake_auth)(SSL *, int) = NULL;\n\nuint32_t (*SSL_SESSION_get_max_early_data)(const SSL_SESSION *) = NULL;\n\nint (*SSL_write_early_data)(SSL *, const void *, size_t, size_t *) = NULL;\n\nint (*SSL_read_early_data)(SSL *, void *, size_t, size_t *) = NULL;\n\nint (*SSL_CTX_set_max_early_data)(SSL_CTX *, uint32_t) = NULL;\n\n#else\n\nstatic const long Cryptography_HAS_TLSv1_3 = 1;\n\n#endif\n\n\n\n#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_111 && !CRYPTOGRAPHY_IS_LIBRESSL\n\nstatic const long Cryptography_HAS_GET_PROTO_VERSION = 0;\n\n\n\nlong (*SSL_CTX_get_min_proto_version)(SSL_CTX *) = NULL;\n\nlong (*SSL_CTX_get_max_proto_version)(SSL_CTX *) = NULL;\n\nlong (*SSL_get_min_proto_version)(SSL *) = NULL;\n\nlong (*SSL_get_max_proto_version)(SSL *) = NULL;\n\n#else\n\nstatic const long Cryptography_HAS_GET_PROTO_VERSION = 1;\n\n#endif\n\n"