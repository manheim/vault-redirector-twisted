"""
redirector/redirector.py

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

import logging
import signal
from os import getpid

logger = logging.getLogger()


class VaultRedirector(object):

    def __init__(self, consul_host_port,
                 redir_to_https=False, redir_to_ip=False, log_disable=False):
        """
        Initialize the redirector service.

        :param consul_host_port: Consul host/IP and port in host:port form
        :type consul_host_port: str
        :param redir_to_https: Redirect to HTTPS if True, otherwise HTTP
        :type redir_to_https: bool
        :param redir_to_ip: Redirect to IP if True, otherwise node name
        :type redir_to_ip: bool
        :param log_disable: If True, do not fire ANY :py:mod:`logging` module
          calls from this class; ignore them all. This can be changed at runtime
          via signals.
        :type log_disable: bool
        """
        self.consul_host_port = consul_host_port
        self.redir_https = redir_to_https
        self.redir_ip = redir_to_ip
        self.log_enabled = not log_disable
        # setup signal handlers for logging enable/disable
        self.setup_signal_handlers()
        if not self.log_enabled:
            # be sure to warn the user of how to enable logging
            logger.warning('Starting VaultRedirector with ALL LOGGING '
                           'DISABLED; send SIGUSR1 to PID %d enable logging.',
                           getpid())

    def setup_signal_handlers(self):
        """
        setup signal handlers for logging enable/disable

        Note that this doesn't work on Windows.
        """
        signal.signal(signal.SIGUSR1, self.handle_logging_signal)
        signal.signal(signal.SIGUSR2, self.handle_logging_signal)

    def handle_logging_signal(self, signum, frame):
        """
        Handle a signal sent to this process (SIGUSR1 or SIGUSR2) to enable or
        disable logging.

        :param signum: signal number sent to process
        :type signum: int
        :param frame: current stack frame when signal was caught
        """
        if signum == signal.SIGUSR1:
            logger.warning('Logging enabled via signal; send SIGUSR2 to PID '
                           '%d to disable logging', getpid())
            self.log_enabled = True
        elif signum == signal.SIGUSR2:
            logger.warning('Logging disabled via signal; send SIGUSR1 to PID '
                           '%d to enable logging', getpid())
            self.log_enabled = False
        # else don't know how we got here, but ignore it

    def run(self):
        pass
