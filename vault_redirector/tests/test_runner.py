"""
redirector/tests/test_runner.py

The latest version of this package is available at:
<https://github.com/manheim/vault-redirector-twisted>

################################################################################
The MIT License (MIT)

Copyright (c) 2016 Manheim, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
################################################################################
While not legally required, I sincerely request that anyone who finds
bugs or makes improvements please submit them at
<https://github.com/manheim/vault-redirector-twisted> so that others can
benefit.
################################################################################
AUTHORS:
Jason Antman <jason@jasonantman.com> <http://www.jasonantman.com>
################################################################################
"""

import sys
import pytest
import logging
from vault_redirector.runner import (Runner, console_entry_point,
                                     set_log_debug, set_log_info,
                                     set_log_level_format)
from vault_redirector.version import (_VERSION, _PROJECT_URL)
from vault_redirector.redirector import VaultRedirector

# https://code.google.com/p/mock/issues/detail?id=249
# py>=3.4 should use unittest.mock not the mock package on pypi
if (
        sys.version_info[0] < 3 or
        sys.version_info[0] == 3 and sys.version_info[1] < 4
):
    IS_PY34PLUS = False
    from mock import patch, call, Mock
else:
    IS_PY34PLUS = True
    from unittest.mock import patch, call, Mock

pbm = 'vault_redirector.runner'  # patch base path for this module
pb = '%s.Runner' % pbm  # patch base for class


class TestConsoleEntryPoint(object):

    def test_console_entry_point(self):
        with patch(pb) as mock_runner:
            console_entry_point()
        assert mock_runner.mock_calls == [
            call(),
            call().console_entry_point()
        ]


class TestRunner(object):

    def setup(self):
        self.cls = Runner()

    def test_parse_args(self):
        ret_mock = Mock()
        type(ret_mock).CONSUL_HOST_PORT = 'foo:123'
        desc = 'Python/Twisted application to redirect Hashicorp Vault client' \
            ' requests to the active node in a HA cluster'
        with patch('%s.argparse.ArgumentParser' % pbm) as mock_parser:
            mock_parser.return_value.parse_args.return_value = ret_mock
            self.cls.parse_args(['foo:123'])
        ver_str = 'vault-redirector {v} (see <{s}> for source code)'.format(
            s=_PROJECT_URL,
            v=_VERSION
        )
        assert mock_parser.mock_calls == [
            call(description=desc),
            call().add_argument('-v', '--verbose', dest='verbose',
                                action='count', default=0,
                                help='verbose output. specify twice for '
                                'debug-level output. See also -l|--log-enable'),
            call().add_argument('-l', '--log-disable', action='store_true',
                                default=False, dest='log_disable',
                                help='If specified, disable ALL logging after '
                                     'initial setup. This can be changed at '
                                     'runtime via signals'),
            call().add_argument('-V', '--version', action='version',
                                version=ver_str),
            call().add_argument('-S', '--https', dest='https',
                                action='store_true',
                                default=False, help='Redirect to HTTPS scheme'
                                ' instead of plain HTTP.'),
            call().add_argument('-I', '--ip', dest='redir_ip',
                                action='store_true', default=False,
                                help='redirect to active node IP instead of '
                                'name'),
            call().add_argument('-p', '--poll-interval', dest='poll_interval',
                                default=5.0, action='store', type=float,
                                help='Consul service health poll interval in '
                                     'seconds (default 5.0)'),
            call().add_argument('-P', '--port', dest='bind_port',
                                action='store', type=int, default=8080,
                                help='Port number to listen on (default 8080)'),
            call().add_argument('-C', '--checkid', dest='checkid',
                                action='store', type=str,
                                default='service:vault', help='Consul service '
                                'CheckID for Vault (default: "service:vault"'),
            call().add_argument('-c', '--cert-path', dest='cert_path', type=str,
                                action='store', help='Path to PEM-encoded TLS '
                                'certificate. If you need a certificate chain '
                                'to verify trust, this file should be composed '
                                'of the server certificate followed by one or '
                                'more chain certificates. If specified, you '
                                'must also specify -k|--key-path'),
            call().add_argument('-k', '--key-path', dest='key_path', type=str,
                                action='store', help='Path to PEM-encoded TLS '
                                'private key. If specified, you must also '
                                'specify -c|--cert-path'),
            call().add_argument('CONSUL_HOST_PORT', action='store', type=str,
                                help='Consul address in host:port form'),
            call().parse_args(['foo:123']),
        ]

    def test_parse_args_verbose1(self):
        res = self.cls.parse_args(['-v', 'foo:123'])
        assert res.verbose == 1
        assert res.CONSUL_HOST_PORT == 'foo:123'

    def test_parse_args_verbose2(self):
        res = self.cls.parse_args(['-vv', 'foo:123'])
        assert res.verbose == 2

    def test_parse_args_log_disable(self):
        res = self.cls.parse_args(['-l', 'foo:123'])
        assert res.log_disable is True

    def test_parse_args_version(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            self.cls.parse_args(['-V'])
        assert excinfo.value.code == 0
        out, err = capsys.readouterr()
        expected = 'vault-redirector ' + _VERSION + ' (see <' + _PROJECT_URL \
                   + '> for source code)' + "\n"
        # argparser's HelpFormatter class limits help output lines to 24 chars
        expected = expected[:73] + "\n" + expected[73:]
        if IS_PY34PLUS:
            # python >= 3.4 argparse outputs version to STDOUT not STDERR;
            # see https://bugs.python.org/issue18920 and
            # https://docs.python.org/3/whatsnew/3.4.html#other-improvements
            assert out == expected
            assert err == ''
        else:
            assert out == ''
            assert err == expected

    def test_parse_args_https(self):
        res = self.cls.parse_args(['-S', 'foo:123'])
        assert res.https is True

    def test_parse_args_ip(self):
        res = self.cls.parse_args(['-I', 'foo:123'])
        assert res.redir_ip is True

    def test_parse_args_poll_interval(self):
        res = self.cls.parse_args(['-p', '1.23', 'foo:123'])
        assert res.poll_interval == 1.23

    def test_parse_args_port(self):
        res = self.cls.parse_args(['-P', '1234', 'foo:123'])
        assert res.bind_port == 1234

    def test_parse_args_checkid(self):
        res = self.cls.parse_args(['-C', 'foo:bar', 'foo:123'])
        assert res.checkid == 'foo:bar'

    def test_parse_args_no_options(self):
        res = self.cls.parse_args(['foo:123'])
        assert res.CONSUL_HOST_PORT == 'foo:123'
        # defaults
        assert res.verbose == 0
        assert res.https is False
        assert res.redir_ip is False
        assert res.log_disable is False
        assert res.poll_interval == 5.0
        assert res.bind_port == 8080
        assert res.checkid == 'service:vault'

    def test_parse_args_none(self):
        with pytest.raises(SystemExit):
            self.cls.parse_args([])

    def test_parse_args_bad_consul(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            self.cls.parse_args(['foo'])
        assert excinfo.value.code == 1
        out, err = capsys.readouterr()
        assert 'ERROR: CONSUL_HOST_PORT must be in host:port or ip:port ' \
               'format' in err

    def test_parse_args_cert_key(self):
        res = self.cls.parse_args(
            ['-c', '/cert/path', '-k', '/key/path', 'foo:123']
        )
        assert res.cert_path == '/cert/path'
        assert res.key_path == '/key/path'

    def test_parse_args_cert_no_key(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            self.cls.parse_args(['-c', '/cert/path', 'foo:123'])
        assert excinfo.value.code == 1
        out, err = capsys.readouterr()
        assert 'ERROR: -k|--key-path and -c|--cert-path must be specified ' \
               'together' in err

    def test_parse_args_key_no_cert(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            self.cls.parse_args(['-k', '/key/path', 'foo:123'])
        assert excinfo.value.code == 1
        out, err = capsys.readouterr()
        assert 'ERROR: -k|--key-path and -c|--cert-path must be specified ' \
               'together' in err

    def test_console_entry_point(self):
        argv = ['/tmp/redirector/runner.py', 'foo:123']
        with patch.object(sys, 'argv', argv):
            with patch(
                    '%s.VaultRedirector' % pbm,
                    spec_set=VaultRedirector
            ) as mock_redir, \
                 patch('%s.logger' % pbm) as mock_logger:
                self.cls.console_entry_point()
        assert mock_redir.mock_calls == [
            call(
                'foo:123', redir_to_https=False, redir_to_ip=False,
                log_disable=False, poll_interval=5.0, bind_port=8080,
                check_id='service:vault', key_path=None, cert_path=None
            ),
            call().run()
        ]
        assert mock_logger.mock_calls == []

    def test_console_entry_point_https(self):
        argv = ['/tmp/redirector/runner.py', '-S', 'foo:123']
        with patch.object(sys, 'argv', argv):
            with patch(
                    '%s.VaultRedirector' % pbm,
                    spec_set=VaultRedirector
            ) as mock_redir, \
                 patch('%s.logger' % pbm) as mock_logger:
                self.cls.console_entry_point()
        assert mock_redir.mock_calls == [
            call(
                'foo:123', redir_to_https=True, redir_to_ip=False,
                log_disable=False, poll_interval=5.0, bind_port=8080,
                check_id='service:vault', key_path=None, cert_path=None
            ),
            call().run()
        ]
        assert mock_logger.mock_calls == []

    def test_console_entry_point_ip(self):
        argv = ['/tmp/redirector/runner.py', '-I', 'foo:123']
        with patch.object(sys, 'argv', argv):
            with patch(
                    '%s.VaultRedirector' % pbm,
                    spec_set=VaultRedirector
            ) as mock_redir, \
                 patch('%s.logger' % pbm) as mock_logger:
                self.cls.console_entry_point()
        assert mock_redir.mock_calls == [
            call(
                'foo:123', redir_to_https=False, redir_to_ip=True,
                log_disable=False, poll_interval=5.0, bind_port=8080,
                check_id='service:vault', key_path=None, cert_path=None
            ),
            call().run()
        ]
        assert mock_logger.mock_calls == []

    def test_console_entry_point_poll_interval(self):
        argv = ['/tmp/redirector/runner.py', '-p', '12.345', 'foo:123']
        with patch.object(sys, 'argv', argv):
            with patch(
                    '%s.VaultRedirector' % pbm,
                    spec_set=VaultRedirector
            ) as mock_redir, \
                 patch('%s.logger' % pbm) as mock_logger:
                self.cls.console_entry_point()
        assert mock_redir.mock_calls == [
            call(
                'foo:123', redir_to_https=False, redir_to_ip=False,
                log_disable=False, poll_interval=12.345, bind_port=8080,
                check_id='service:vault', key_path=None, cert_path=None
            ),
            call().run()
        ]
        assert mock_logger.mock_calls == []

    def test_console_entry_port(self):
        argv = ['/tmp/redirector/runner.py', '-P', '1234', 'foo:123']
        with patch.object(sys, 'argv', argv):
            with patch(
                    '%s.VaultRedirector' % pbm,
                    spec_set=VaultRedirector
            ) as mock_redir, \
                 patch('%s.logger' % pbm) as mock_logger:
                self.cls.console_entry_point()
        assert mock_redir.mock_calls == [
            call(
                'foo:123', redir_to_https=False, redir_to_ip=False,
                log_disable=False, poll_interval=5.0, bind_port=1234,
                check_id='service:vault', key_path=None, cert_path=None
            ),
            call().run()
        ]
        assert mock_logger.mock_calls == []

    def test_console_entry_checkid(self):
        argv = ['/tmp/redirector/runner.py', '-C', 'foo:bar', 'foo:123']
        with patch.object(sys, 'argv', argv):
            with patch(
                    '%s.VaultRedirector' % pbm,
                    spec_set=VaultRedirector
            ) as mock_redir, \
                 patch('%s.logger' % pbm) as mock_logger:
                self.cls.console_entry_point()
        assert mock_redir.mock_calls == [
            call(
                'foo:123', redir_to_https=False, redir_to_ip=False,
                log_disable=False, poll_interval=5.0, bind_port=8080,
                check_id='foo:bar', key_path=None, cert_path=None
            ),
            call().run()
        ]
        assert mock_logger.mock_calls == []

    def test_console_entry_point_log_disable(self):
        argv = ['/tmp/redirector/runner.py', '-l', 'foo:123']
        with patch.object(sys, 'argv', argv):
            with patch(
                    '%s.VaultRedirector' % pbm,
                    spec_set=VaultRedirector
            ) as mock_redir, \
                 patch('%s.logger' % pbm) as mock_logger:
                self.cls.console_entry_point()
        assert mock_redir.mock_calls == [
            call(
                'foo:123', redir_to_https=False, redir_to_ip=False,
                log_disable=True, poll_interval=5.0, bind_port=8080,
                check_id='service:vault', key_path=None, cert_path=None
            ),
            call().run()
        ]
        assert mock_logger.mock_calls == []

    def test_console_entry_point_tls(self):
        argv = [
            '/tmp/redirector/runner.py',
            '-c', '/path/to/cert',
            '-k', '/path/to/key',
            'foo:123'
        ]
        with patch.object(sys, 'argv', argv):
            with patch(
                    '%s.VaultRedirector' % pbm,
                    spec_set=VaultRedirector
            ) as mock_redir, \
                 patch('%s.logger' % pbm) as mock_logger:
                self.cls.console_entry_point()
        assert mock_redir.mock_calls == [
            call(
                'foo:123', redir_to_https=False, redir_to_ip=False,
                log_disable=False, poll_interval=5.0, bind_port=8080,
                check_id='service:vault',
                key_path='/path/to/key', cert_path='/path/to/cert'
            ),
            call().run()
        ]
        assert mock_logger.mock_calls == []

    def test_console_entry_point_verbose1(self):
        argv = ['/tmp/redirector/runner.py', '-v', 'foo:123']
        with patch.object(sys, 'argv', argv):
            with patch(
                    '%s.VaultRedirector' % pbm,
                    spec_set=VaultRedirector
            ) as mock_redir, \
                 patch('%s.set_log_info' % pbm) as mock_set_info, \
                 patch('%s.logger' % pbm) as mock_logger:
                self.cls.console_entry_point()
        assert mock_redir.mock_calls == [
            call(
                'foo:123', redir_to_https=False, redir_to_ip=False,
                log_disable=False, poll_interval=5.0, bind_port=8080,
                check_id='service:vault', key_path=None, cert_path=None
            ),
            call().run()
        ]
        assert mock_logger.mock_calls == []
        assert mock_set_info.mock_calls == [call()]

    def test_console_entry_point_verbose2(self):
        argv = ['/tmp/redirector/runner.py', '-vv', 'foo:123']
        with patch.object(sys, 'argv', argv):
            with patch(
                    '%s.VaultRedirector' % pbm,
                    spec_set=VaultRedirector
            ) as mock_redir, \
                 patch('%s.set_log_debug' % pbm) as mock_set_debug, \
                 patch('%s.logger' % pbm) as mock_logger:
                self.cls.console_entry_point()
        assert mock_redir.mock_calls == [
            call(
                'foo:123', redir_to_https=False, redir_to_ip=False,
                log_disable=False, poll_interval=5.0, bind_port=8080,
                check_id='service:vault', key_path=None, cert_path=None
            ),
            call().run()
        ]
        assert mock_logger.mock_calls == []
        assert mock_set_debug.mock_calls == [call()]

    def test_set_log_info(self):
        with patch('%s.set_log_level_format' % pbm) as mock_set:
            set_log_info()
        assert mock_set.mock_calls == [
            call(logging.INFO, '%(asctime)s %(levelname)s:%(name)s:%(message)s')
        ]

    def test_set_log_debug(self):
        with patch('%s.set_log_level_format' % pbm) as mock_set:
            set_log_debug()
        assert mock_set.mock_calls == [
            call(logging.DEBUG,
                 "%(asctime)s [%(levelname)s %(filename)s:%(lineno)s - "
                 "%(name)s.%(funcName)s() ] %(message)s")
        ]

    def test_set_log_level_format(self):
        mock_handler = Mock(spec_set=logging.Handler)
        with patch('%s.logger' % pbm) as mock_logger:
            with patch('%s.logging.Formatter' % pbm) as mock_formatter:
                type(mock_logger).handlers = [mock_handler]
                set_log_level_format(5, 'foo')
        assert mock_formatter.mock_calls == [
            call(fmt='foo')
        ]
        assert mock_handler.mock_calls == [
            call.setFormatter(mock_formatter.return_value)
        ]
        assert mock_logger.mock_calls == [
            call.setLevel(5)
        ]
