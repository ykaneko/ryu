# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import inspect
import logging
import os
import os.path
import sys

LOG = logging.getLogger('ryu.utils')


def _abspath(path):
    if path == '':
        path = '.'
    return os.path.abspath(path)


def _split_modname(modpath):
    sys_path = [_abspath(path) for path in sys.path]
    modname = os.path.basename(modpath)
    dirname = os.path.dirname(modpath)
    while True:
        if dirname in sys_path:
            break
        if not os.path.exists(os.path.join(dirname, '__init__.py')):
            break

        basename = os.path.basename(dirname)
        if basename:
            old_dirname = dirname
            dirname = os.path.dirname(dirname)
            if old_dirname == dirname:
                break
            if modname:
                modname = basename + '.' + modname
            else:
                modname = basename
        else:
            break

    return dirname, modname


def _import(modname):
    __import__(modname)
    return sys.modules[modname]


def import_module(modname):
    try:
        return _import(modname)
    except ImportError:
        pass

    if modname.endswith('.py'):
        modname = modname[:-3]
        try:
            return _import(modname)
        except ImportError:
            pass

    modname = os.path.abspath(modname)
    dirname, name = _split_modname(modname)
    if dirname not in [_abspath(path) for path in sys.path]:
        sys.path.append(dirname)
    return _import(name)


RYU_DEFAULT_FLAG_FILE = ('ryu.conf', 'etc/ryu/ryu.conf' '/etc/ryu/ryu.conf')


def find_flagfile(default_path=RYU_DEFAULT_FLAG_FILE):
    if '--flagfile' in sys.argv:
        return

    script_dir = os.path.dirname(inspect.stack()[-1][1])

    for filename in default_path:
        if not os.path.isabs(filename):
            if os.path.exists(filename):
                # try relative to current path
                filename = os.path.abspath(filename)
            elif os.path.exists(os.path.join(script_dir, filename)):
                # try relative to script dir
                filename = os.path.join(script_dir, filename)

        if not os.path.exists(filename):
            continue

        flagfile = '--flagfile=%s' % filename
        sys.argv.insert(1, flagfile)
        LOG.debug('flagfile = %s', filename)
        return


def round_up(x, y):
    return ((x + y - 1) / y) * y


def hex_array(data):
    return ' '.join(hex(ord(chr)) for chr in data)
