project('bubblewrap', 'c', version : '0.1.5')

cc = meson.get_compiler('c')

assert(cc.has_header('sys/capability.h'), 'Capability header missing.')
selinux_dep = dependency('libselinux', version : '>=2.1.9', required : false)

add_project_arguments('-D_GNU_SOURCE', language : 'c')

cdata = configuration_data()

cdata.set_quoted('PACKAGE_STRING', 'bubblewrap')
if selinux_dep.found()
  cdata.set('HAVE_SELINUX', 1)
endif
configure_file(input : 'config.h.meson',
  output : 'config.h',
  configuration : cdata)

bwrap_sources = [
  'bubblewrap.c',
  'bind-mount.c',
  'network.c',
  'utils.c',
]

executable('bwrap', bwrap_sources, install : true, dependencies : selinux_dep)

xsltproc = find_program('xsltproc', required : false)

if xsltproc.found()
  custom_target('manpage',
    output : 'bwrap.1',
    input : 'bwrap.xml',
    command : [xsltproc,
      '-o', '@OUTPUT@',
      '--nonet',
      '--stringparam', 'man.output.quietly', '1',
      '--stringparam', 'funcsynopsis.style', 'ansi',
      '--stringparam', 'man.th.extra1.suppress', '1',
      '--stringparam', 'man.authors.section.enabled', '0',
      '--stringparam', 'man.copyright.section.enabled', '0',
      'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl',
      '@INPUT@',
      ],
    install : true,
    install_dir : join_paths(get_option('mandir'), 'man1'),
  )
endif

install_data('completions/bash/bwrap',
  install_dir : join_paths(get_option('datadir'), 'bash-completion/completions')
  )
