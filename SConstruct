# Licensed to Cloudkick, Inc under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# Cloudkick licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


EnsureSConsVersion(1, 1, 0)

import os
import re
import fnmatch
from os.path import join as pjoin
from site_scons import ac

opts = Variables('build.py')

opts.Add(PathVariable('CURL', 'Path to curl-config', WhereIs('curl-config')))

env = Environment(options=opts,
                  ENV = os.environ.copy(),
                  tools=['default', 'subst', 'packaging', 'install'])

#TODO: convert this to a configure builder, so it gets cached
def read_version(prefix, path):
  version_re = re.compile("(.*)%s_VERSION_(?P<id>MAJOR|MINOR|PATCH)(\s+)(?P<num>\d)(.*)" % prefix)
  versions = {}
  fp = open(path, 'rb')
  for line in fp.readlines():
    m = version_re.match(line)
    if m:
      versions[m.group('id')] = int(m.group('num'))
  fp.close()
  return (versions['MAJOR'], versions['MINOR'], versions['PATCH'])

env['version_major'], env['version_minor'], env['version_patch'] = read_version('CKL', 'src/ckl_version.h')
env['version_string'] = "%d.%d.%d"  % (env['version_major'], env['version_minor'], env['version_patch'])

dvpath = "/etc/debian_version"
if os.path.exists(dvpath):
  contents = open(dvpath).read().strip()
  # TODO: don't hard code this
  if contents == "4.0":
    env['version_string'] += "~bpo40"


conf = Configure(env, custom_tests = {'CheckCurlPrefix': ac.CheckCurlPrefix,
                                      'CheckCurlLibs': ac.CheckCurlLibs,
                                      'CheckDpkgArch': ac.CheckDpkgArch})

cc = conf.env.WhereIs('/Developer/usr/bin/clang')
if os.environ.has_key('CC'):
  cc = os.environ['CC']

if cc:
  conf.env['CC'] = cc

# Include libssl and libcrypto on Mac OS X.
# See https://github.com/pquerna/ckl/issues/3
if os.uname()[0]:
  conf.env.AppendUnique(LIBS=['ssl', 'crypto'])

if not conf.CheckFunc('floor'):
  conf.env.AppendUnique(LIBS=['m'])

if conf.CheckLib('util', symbol='openpty'):
  conf.env.AppendUnique(LIBS=['util'])

cprefix = conf.CheckCurlPrefix()
if not cprefix[0]:
  Exit("Error: Unable to detect curl prefix")

clibs = conf.CheckCurlLibs()
if not clibs[0]:
  Exit("Error: Unable to detect curl libs")

if conf.env.WhereIs('dpkg'):
  conf.env['HAVE_DPKG'] = True
  (st, env['debian_arch']) = conf.CheckDpkgArch()
  if not st:
    Exit()

if conf.env.WhereIs('rpmbuild'):
    conf.env['HAVE_RPMBUILD'] = True

conf.env.AppendUnique(CPPPATH = [pjoin(cprefix[1], "include"), "#"])

# TOOD: this is less than optimal, since curl-config polutes this quite badly :(
t = clibs[1].replace('-g0 ', '')
t = t.replace('-Wno-system-headers ', '')
t = t.replace('-Os ', '')
d = conf.env.ParseFlags(t)
conf.env.MergeFlags(d)
conf.env.AppendUnique(CPPFLAGS = ["-Wall", '-O0', '-ggdb'])
# this is needed on solaris because of its dumb library path issues
conf.env.AppendUnique(RPATH = conf.env.get('LIBPATH'))
env = conf.Finish()

Export("env")

extern = SConscript("extern/SConscript")

Export("extern")

ckl = SConscript("src/SConscript")

targets = [ckl]
target_packages = []

def locate(pattern, root=os.curdir):
    '''Locate all files matching supplied filename pattern in and below
    supplied root directory.'''
    for path, dirs, files in os.walk(os.path.abspath(root)):
        for filename in fnmatch.filter(files, pattern):
            yield os.path.join(path, filename)

site_files = []
site_files.extend(env.Glob("site_scons/*/*.py"))
site_files.extend(env.Glob("site_scons/*.py"))
site_files.extend(env.Glob("src/*.h"))
site_files.extend(env.Glob("build.py"))
site_files.extend(locate('*', 'extern'))
env.Depends('.', site_files)

if env.get('HAVE_RPMBUILD'):
  env.Install('/usr/bin/', ckl[0])
  packaging = {'NAME': 'ckl',
                'VERSION': env['version_string'],
                'PACKAGEVERSION':  0,
                'LICENSE': 'Proprietary',
                'SUMMARY': 'Cloudkick Changelog tool',
                'DESCRIPTION': 'Cloudkick Changelog tool',
                'X_RPM_GROUP': 'System/Monitoring',
                'source': [],
                'PACKAGETYPE': 'rpm'}
  target_packages.append(env.Package(**packaging))

if env.get('HAVE_DPKG'):
  subst = {}
  pkgbase = "%s-%s" % ("ckl", env['version_string'])
  debname = pkgbase + "_" + env['debian_arch'] +".deb"
  substkeys = Split("""
  version_string
  debian_arch""")

  for x in substkeys:
      subst['%' + str(x) + '%'] = str(env.get(x))

  deb_control = env.SubstFile('packaging/debian.control.in', SUBST_DICT = subst)
  deb_conffiles = env.SubstFile('packaging/debian.conffiles.in', SUBST_DICT = subst)
  deb_postinst = env.SubstFile('packaging/debian.postinst.in', SUBST_DICT = subst)
  fr = ""
  if env.WhereIs('fakeroot'):
    fr = env.WhereIs('fakeroot')
  debroot = "debian_temproot"
  deb = env.Command(debname, [ckl[0], deb_control, deb_conffiles, deb_postinst],
                [
                  Delete(debroot),
                  Mkdir(debroot),
                  Mkdir(pjoin(debroot, "DEBIAN")),
                  Copy(pjoin(debroot, 'DEBIAN', 'control'), deb_control[0]),
                  Copy(pjoin(debroot, 'DEBIAN', 'conffiles'), deb_conffiles[0]),
                  Copy(pjoin(debroot, 'DEBIAN', 'postinst'), deb_postinst[0]),
                  Chmod(pjoin(debroot, 'DEBIAN', 'postinst'), 0755),
                  Mkdir(pjoin(debroot, "usr", "bin")),
                  Copy(pjoin(debroot, "usr", "bin", 'ckl'), ckl[0][0]),
                  fr +" dpkg-deb -b "+debroot+" $TARGET",
                  Delete(debroot),
                ])

  target_packages.append(deb)
targets.extend(target_packages)

env.Default(targets)
