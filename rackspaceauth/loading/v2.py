# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from keystoneauth1 import loading
from rackspaceauth import v2


class APIKey(loading.BaseV2Loader):

    @property
    def plugin_class(self):
        return v2.APIKey

    def get_options(self):
        options = super(APIKey, self).get_options()

        options.extend([
            loading.Opt('username',
                        help='Username'),
            loading.Opt('api-key',
                        dest='api_key',
                        help='API Key'),
        ])
        return options


class Password(loading.BaseV2Loader):

    @property
    def plugin_class(self):
        return v2.Password

    def get_options(self):
        options = super(Password, self).get_options()

        options.extend([
            loading.Opt('username',
                        help='Username'),
            loading.Opt('password',
                        help='Password'),
        ])
        return options


class Token(loading.BaseV2Loader):

    @property
    def plugin_class(self):
        return v2.Token

    def get_options(self):
        options = super(Token, self).get_options()

        options.extend([
            loading.Opt('tenant-id',
                        dest='tenant_id',
                        help='Tenant ID'),
            loading.Opt('token',
                        help='Token'),
        ])
        return options


class RSAToken(loading.BaseV2Loader):

    @property
    def plugin_class(self):
        return v2.RSAToken

    def get_options(self):
        options = super(RSAToken, self).get_options()

        options.extend([
            loading.Opt('token',
                        help='RSA Token'),
            loading.Opt('username',
                        help='Username')
        ])
        return options
