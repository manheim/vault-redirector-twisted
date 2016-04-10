"""
redirector/tests/test_redirector.py

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
from vault_redirector.redirector import VaultRedirector
import signal

# https://code.google.com/p/mock/issues/detail?id=249
# py>=3.4 should use unittest.mock not the mock package on pypi
if (
        sys.version_info[0] < 3 or
        sys.version_info[0] == 3 and sys.version_info[1] < 4
):
    from mock import patch, call, Mock
else:
    from unittest.mock import patch, call, Mock

pbm = 'vault_redirector.redirector'  # patch base path for this module
pb = '%s.VaultRedirector' % pbm  # patch base for class


class TestVaultRedirector(object):

    def setup(self):
        with patch('%s.setup_signal_handlers' % pb):
            self.cls = VaultRedirector('consul:123')

    def test_init(self):
        with patch('%s.setup_signal_handlers' % pb) as mock_setup_signals:
            with patch('%s.logger' % pbm) as mock_logger:
                cls = VaultRedirector('consul:123')
        assert mock_setup_signals.mock_calls == [call()]
        assert mock_logger.mock_calls == []
        assert cls.consul_host_port == 'consul:123'
        assert cls.redir_https is False
        assert cls.redir_ip is False
        assert cls.log_enabled is True

    def test_init_nondefault(self):
        with patch('%s.setup_signal_handlers' % pb) as mock_setup_signals:
            with patch('%s.logger' % pbm) as mock_logger:
                with patch('%s.getpid' % pbm) as mock_getpid:
                    mock_getpid.return_value = 12345
                    cls = VaultRedirector(
                        'consul:123',
                        redir_to_https=True,
                        redir_to_ip=True,
                        log_disable=True
                    )
        assert mock_setup_signals.mock_calls == [call()]
        assert mock_logger.mock_calls == [
            call.warning(
                'Starting VaultRedirector with ALL LOGGING DISABLED; send '
                'SIGUSR1 to PID %d enable logging.',
                12345
            )
        ]
        assert cls.consul_host_port == 'consul:123'
        assert cls.redir_https is True
        assert cls.redir_ip is True
        assert cls.log_enabled is False

    def test_setup_signal_handlers(self):
        with patch('%s.signal.signal' % pbm) as mock_signal:
            self.cls.setup_signal_handlers()
        assert mock_signal.mock_calls == [
            call(signal.SIGUSR1, self.cls.handle_logging_signal),
            call(signal.SIGUSR2, self.cls.handle_logging_signal),
        ]

    def test_handle_logging_signal_USR1(self):
        self.cls.log_enabled = False
        with patch('%s.logger' % pbm) as mock_logger:
            with patch('%s.getpid' % pbm) as mock_getpid:
                mock_getpid.return_value = 12345
                self.cls.handle_logging_signal(signal.SIGUSR1, None)
        assert mock_logger.mock_calls == [
            call.warning('Logging enabled via signal; send SIGUSR2 to PID %d '
                         'to disable logging', 12345)
        ]
        assert self.cls.log_enabled is True

    def test_handle_logging_signal_USR2(self):
        self.cls.log_enabled = True
        with patch('%s.logger' % pbm) as mock_logger:
            with patch('%s.getpid' % pbm) as mock_getpid:
                mock_getpid.return_value = 12345
                self.cls.handle_logging_signal(signal.SIGUSR2, None)
        assert mock_logger.mock_calls == [
            call.warning('Logging disabled via signal; send SIGUSR1 to PID %d '
                         'to enable logging', 12345)
        ]
        assert self.cls.log_enabled is False

    def test_handle_logging_signal_other(self):
        self.cls.log_enabled = True
        with patch('%s.logger' % pbm) as mock_logger:
            with patch('%s.getpid' % pbm) as mock_getpid:
                mock_getpid.return_value = 12345
                self.cls.handle_logging_signal(signal.SIGABRT, None)
        assert mock_logger.mock_calls == []
        assert self.cls.log_enabled is True