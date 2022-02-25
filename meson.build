project(
  'bubblewrap',
  'c',
  version : '0.6.1',
  meson_version : '>=0.49.0',
  default_options : [
    'warning_level=2',
  ],
)

cc = meson.get_compiler('c')
add_project_arguments('-D_GNU_SOURCE', language : 'c')
common_include_directories = include_directories('.')

# Keep this in sync with ostree, except remove -Wall (part of Meson
# warning_level 2) and -Werror=declaration-after-statement
add_project_arguments(
  cc.get_supported_arguments([
    '-Werror=shadow',
    '-Werror=empty-body',
    '-Werror=strict-prototypes',
    '-Werror=missing-prototypes',
    '-Werror=implicit-function-declaration',
    '-Werror=pointer-arith',
    '-Werror=init-self',
    '-Werror=missing-declarations',
    '-Werror=return-type',
    '-Werror=overflow',
    '-Werror=int-conversion',
    '-Werror=parenthesis',
    '-Werror=incompatible-pointer-types',
    '-Werror=misleading-indentation',
    '-Werror=missing-include-dirs',
    '-Werror=aggregate-return',

    # Extra warnings specific to bubblewrap
    '-Werror=switch-default',
    '-Wswitch-enum',

    # Meson warning_level=2 would do this, but we are not fully
    # signedness-safe yet
    '-Wno-sign-compare',
    '-Wno-error=sign-compare',

    # Deliberately not warning about these, ability to zero-initialize
    # a struct is a feature
    '-Wno-missing-field-initializers',
    '-Wno-error=missing-field-initializers',
  ]),
  language : 'c',
)

if (
  cc.has_argument('-Werror=format=2')
  and cc.has_argument('-Werror=format-security')
  and cc.has_argument('-Werror=format-nonliteral')
)
  add_project_arguments([
    '-Werror=format=2',
    '-Werror=format-security',
    '-Werror=format-nonliteral',
  ], language : 'c')
endif

bash = find_program('bash', required : false)

if get_option('python') == ''
  python = find_program('python3')
else
  python = find_program(get_option('python'))
endif

libcap_dep = dependency('libcap', required : true)

selinux_dep = dependency(
  'libselinux',
  version : '>=2.1.9',
  # if disabled, Meson will behave as though libselinux was not found
  required : get_option('selinux'),
)

cdata = configuration_data()
cdata.set_quoted(
  'PACKAGE_STRING',
  '@0@ @1@'.format(meson.project_name(), meson.project_version()),
)

if selinux_dep.found()
  cdata.set('HAVE_SELINUX', 1)
  if selinux_dep.version().version_compare('>=2.3')
    cdata.set('HAVE_SELINUX_2_3', 1)
  endif
endif

if get_option('require_userns')
  cdata.set('ENABLE_REQUIRE_USERNS', 1)
endif

configure_file(
  output : 'config.h',
  configuration : cdata,
)

if meson.is_subproject()
  bwrapdir = get_option('libexecdir')

  if get_option('program_prefix') == ''
    error('program_prefix option must be set when bwrap is a subproject')
  endif
else
  bwrapdir = get_option('bindir')
endif

bwrap = executable(
  get_option('program_prefix') + 'bwrap',
  [
    'bubblewrap.c',
    'bind-mount.c',
    'network.c',
    'utils.c',
  ],
  install : true,
  install_dir : bwrapdir,
  dependencies : [selinux_dep, libcap_dep],
)

xsltproc = find_program('xsltproc', required : get_option('man'))

if xsltproc.found() and not meson.is_subproject()
  custom_target(
    'bwrap.1',
    output : 'bwrap.1',
    input : 'bwrap.xml',
    command : [
      xsltproc,
      '--nonet',
      '--stringparam', 'man.output.quietly', '1',
      '--stringparam', 'funcsynopsis.style', 'ansi',
      '--stringparam', 'man.th.extra1.suppress', '1',
      '--stringparam', 'man.authors.section.enabled', '0',
      '--stringparam', 'man.copyright.section.enabled', '0',
      '-o', '@OUTPUT@',
      'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl',
      '@INPUT@',
    ],
    install : true,
    install_dir : get_option('mandir') / 'man1',
  )
endif

if not meson.is_subproject()
  subdir('completions')
endif

subdir('tests')
