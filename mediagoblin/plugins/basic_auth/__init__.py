# GNU MediaGoblin -- federated, autonomous media hosting
# Copyright (C) 2011, 2012 MediaGoblin contributors.  See AUTHORS.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from mediagoblin.plugins.basic_auth import forms as auth_forms
from mediagoblin.plugins.basic_auth import tools as auth_tools
from mediagoblin.auth.tools import create_basic_user
from mediagoblin.db.models import User
from mediagoblin.tools import pluginapi
from sqlalchemy import or_

##########################OpenID#########################
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse

import time
import Cookie
import cgi
import cgitb
import sys

def quoteattr(s):
    qs = cgi.escape(s, 1)
    return '"%s"' % (qs,)

try:
    import openid
except ImportError:
    sys.stderr.write("""
Failed to import the OpenID library. In order to use this example, you
must either install the library (see INSTALL in the root of the
distribution) or else add the library to python's import path (the
PYTHONPATH environment variable).

For more information, see the README in the root of the library
distribution.""")
    sys.exit(1)

from openid.extensions import sreg
from openid.server import server
from openid.store.filestore import FileOpenIDStore
from openid.consumer import discover

##########################OpenID#########################

def setup_plugin():
    config = pluginapi.get_config('mediagoblin.plugins.basic_auth')


def get_user(**kwargs):
    username = kwargs.pop('username', None)
    if username:
        user = User.query.filter(
            or_(
                User.username == username,
                User.email == username,
            )).first()
        return user


def create_user(registration_form):
    user = get_user(username=registration_form.username.data)
    if not user and 'password' in registration_form:
        user = create_basic_user(registration_form)
        user.pw_hash = gen_password_hash(
            registration_form.password.data)
        user.save()
    return user


def get_login_form(request):
    return auth_forms.LoginForm(request.form)


def get_registration_form(request):
    return auth_forms.RegistrationForm(request.form)


def gen_password_hash(raw_pass, extra_salt=None):
    return auth_tools.bcrypt_gen_password_hash(raw_pass, extra_salt)


def check_password(raw_pass, stored_hash, extra_salt=None):
    if stored_hash:
        return auth_tools.bcrypt_check_password(raw_pass,
                                                stored_hash, extra_salt)
    return None


def auth():
    return True


def append_to_global_context(context):
    context['pass_auth'] = True
    return context


hooks = {
    'setup': setup_plugin,
    'authentication': auth,
    'auth_get_user': get_user,
    'auth_create_user': create_user,
    'auth_get_login_form': get_login_form,
    'auth_get_registration_form': get_registration_form,
    'auth_gen_password_hash': gen_password_hash,
    'auth_check_password': check_password,
    'auth_fake_login_attempt': auth_tools.fake_login_attempt,
    'template_global_context': append_to_global_context,
}
