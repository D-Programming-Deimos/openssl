project('openssld', ['d'], version: '1.1.0h')

openssl_dep = dependency('openssl')

install_subdir(
	'deimos',
	install_dir: join_paths(get_option('includedir'), 'd', 'openssld'),
)

pkgc = import ('pkgconfig')

pkgc.generate(
	name: 'openssld',
	subdirs: 'd/openssld',
	requires: openssl_dep,
	description: 'OpenSSL D interface',
)
