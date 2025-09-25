code = 'int main() { return 0; }'
cc = meson.get_compiler('c')
flags = []
vs_flags = '-Wl,--version-script=' + meson.current_source_dir() + '/libjose.map'
regex_flags = [ '-export-symbols-regex=^jose_.*' ]

if build_machine.system() == 'darwin'
  # On macOS, the linker does not support version scripts or export-symbols-regex.
  # We rely on default symbol visibility by providing no special flags.
  message('Using default symbol visibility for macOS')
elif build_machine.system() == 'freebsd'
  if cc.links(code, args: vs_flags + ',--undefined-version' , name: 'version script on FreeBSD')
      flags = vs_flags
  else
      flags = regex_flags
  endif
else
  if cc.links(code, args: vs_flags, name: 'version script')
      flags = vs_flags
  else
      flags = regex_flags
  endif
endif

libjose_lib = shared_library('jose',
  'misc.c',
  'misc.h',
  'cfg.c',
  'io.c',
  'b64.c',
  'hsh.c',
  'hsh.h',
  'hooks.c',
  'hooks.h',
  'jwk.c',
  'jws.c',
  'jwe.c',
  'zlib/deflate.c',
  'openssl/aescbch.c',
  'openssl/aesgcm.c',
  'openssl/aesgcmkw.c',
  'openssl/aeskw.c',
  'openssl/compat.c',
  'openssl/compat.h',
  'openssl/dir.c',
  'openssl/ec.c',
  'openssl/ecdh.c',
  'openssl/ecdhes.c',
  'openssl/ecmr.c',
  'openssl/ecdsa.c',
  'openssl/hash.c',
  'openssl/hmac.c',
  'openssl/jwk.c',
  'openssl/lock.c',
  'openssl/misc.c',
  'openssl/misc.h',
  'openssl/oct.c',
  'openssl/pbes2.c',
  'openssl/rsa.c',
  'openssl/rsaes.c',
  'openssl/rsassa.c',

  include_directories: incdir,
  dependencies: [zlib, jansson, libcrypto, threads],
  version: '0.0.0',
  link_args: flags,
  install: true
)

libjose_dep = declare_dependency(
  include_directories: incdir,
  dependencies: jansson,
  link_with: libjose_lib
)
