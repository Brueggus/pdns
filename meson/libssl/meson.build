opt_libssl = get_option('tls-libssl')
opt_libssl_dir = get_option('tls-libssl-dir')


if opt_libssl_dir != ''
  dep_libssl = declare_dependency(
    dependencies: [dep_libcrypto],
    include_directories: [opt_libssl_dir / 'include'],
    link_args: ['-L' + opt_libssl_dir / 'lib', '-lssl'],
  )
else
  dep_libssl = dependency('libssl', required: opt_libssl)
endif

if dep_libssl.found()
  funcs = [
    'SSL_CTX_set_ciphersuites',
    'SSL_CTX_set_num_tickets',
    'SSL_CTX_set_keylog_callback',
    'SSL_CTX_get0_privatekey',
    'SSL_set_hostflags',
    'SSL_CTX_set_alpn_protos',
    'SSL_CTX_set_next_proto_select_cb',
    'SSL_get0_alpn_selected',
    'SSL_get0_next_proto_negotiated',
    'SSL_CTX_set_alpn_select_cb',
    'SSL_CTX_use_cert_and_key',
    'TLS_client_method',
  ]

  foreach func: funcs
    has = cxx.has_function(func, dependencies: dep_libssl)
    conf.set('HAVE_' + func.to_upper(), has, description: 'Have OpenSSL libssl ' + func)
  endforeach

  has = cxx.has_header_symbol(
    'openssl/ssl.h',
    'SSL_CTX_set_min_proto_version',
    dependencies: dep_libssl,
  )
  conf.set(
    'HAVE_SSL_CTX_SET_MIN_PROTO_VERSION',
    has,
    description: 'Have OpenSSL libssl SSL_CTX_set_min_proto_version',
  )

  has_ech_header = cxx.has_header('openssl/ech.h', dependencies: dep_libssl)
  conf.set('HAVE_OPENSSL_ECH_H', has_ech_header, description: 'Have OpenSSL ECH header')
  has_ech_store_read_pem = false
  has_ssl_ctx_set1_echstore = false
  if has_ech_header
    has_ech_store_read_pem = cxx.has_function(
      'OSSL_ECHSTORE_read_pem',
      dependencies: dep_libssl,
      prefix: '#include <openssl/ech.h>',
    )
    has_ssl_ctx_set1_echstore = cxx.has_function(
      'SSL_CTX_set1_echstore',
      dependencies: dep_libssl,
      prefix: '''#include <openssl/ech.h>
#include <openssl/ssl.h>''',
    )
  endif
  conf.set('HAVE_OSSL_ECHSTORE_READ_PEM', has_ech_store_read_pem, description: 'Have OpenSSL libssl OSSL_ECHSTORE_read_pem')
  conf.set('HAVE_SSL_CTX_SET1_ECHSTORE', has_ssl_ctx_set1_echstore, description: 'Have OpenSSL libssl SSL_CTX_set1_echstore')
  conf.set('HAVE_LIBSSL_ECH', has_ech_header and has_ech_store_read_pem and has_ssl_ctx_set1_echstore, description: 'Have OpenSSL server-side ECH support')
endif

conf.set('HAVE_LIBSSL', dep_libssl.found(), description: 'OpenSSL libssl')
summary('OpenSSL libssl', dep_libssl.found(), bool_yn: true, section: 'Crypto')
