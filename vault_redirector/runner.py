"""
redirector/runner.py

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
import argparse
import logging
import re

from .version import _VERSION, _PROJECT_URL
from .redirector import VaultRedirector

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger()

# suppress requests internal logging below WARNING level
requests_log = logging.getLogger("requests")
requests_log.setLevel(logging.WARNING)
requests_log.propagate = True


class Runner(object):

    def parse_args(self, argv):
        """
        parse arguments/options

        :param argv: argument list to parse, usually ``sys.argv[1:]``
        :type argv: list
        :returns: parsed arguments
        :rtype: :py:class:`argparse.Namespace`
        """
        desc = 'Python/Twisted application to redirect Hashicorp Vault client' \
            ' requests to the active node in a HA cluster'
        p = argparse.ArgumentParser(description=desc)
        p.add_argument('-v', '--verbose', dest='verbose', action='count',
                       default=0,
                       help='verbose output. specify twice for debug-level '
                       'output. See also -l|--log-enable')
        ver_str = 'vault-redirector {v} (see <{s}> for source code)'.format(
            s=_PROJECT_URL,
            v=_VERSION
        )
        p.add_argument('-l', '--log-disable', action='store_true',
                       default=False, dest='log_disable',
                       help='If specified, disable ALL logging after initial '
                            'setup. This can be changed at runtime via signals')
        p.add_argument('-V', '--version', action='version', version=ver_str)
        p.add_argument('-S', '--https', dest='https', action='store_true',
                       default=False, help='Redirect to HTTPS scheme instead '
                       'of plain HTTP.')
        p.add_argument('-I', '--ip', dest='redir_ip',
                       action='store_true', default=False,
                       help='redirect to active node IP instead of name')
        p.add_argument('-p', '--poll-interval', dest='poll_interval',
                       default=5.0, action='store', type=float,
                       help='Consul service health poll interval in seconds'
                            ' (default 5.0)')
        p.add_argument('-P', '--port', dest='bind_port', action='store',
                       type=int, default=8080,
                       help='Port number to listen on (default 8080)')
        p.add_argument('-C', '--checkid', dest='checkid', action='store',
                       type=str, default='service:vault', help='Consul service '
                       'CheckID for Vault (default: "service:vault"')
        p.add_argument('-c', '--cert-path', dest='cert_path', type=str,
                       action='store', help='Path to PEM-encoded TLS '
                       'certificate. If you need a certificate chain to verify'
                       ' trust, this file should be composed of the server '
                       'certificate followed by one or more chain certificates.'
                       ' If specified, you must also specify -k|--key-path')
        p.add_argument('-k', '--key-path', dest='key_path', type=str,
                       action='store', help='Path to PEM-encoded TLS private '
                       'key. If specified, you must also specify '
                       '-c|--cert-path')
        p.add_argument('CONSUL_HOST_PORT', action='store', type=str,
                       help='Consul address in host:port form')
        args = p.parse_args(argv)

        if not re.match(r'^.*:\d+$', args.CONSUL_HOST_PORT):
            sys.stderr.write('ERROR: CONSUL_HOST_PORT must be in host:port '
                             "or ip:port format\n")
            raise SystemExit(1)

        if (args.cert_path and not args.key_path) or (
                args.key_path and not args.cert_path
        ):
            sys.stderr.write("ERROR: -k|--key-path and -c|--cert-path must "
                             "be specified together\n")
            raise SystemExit(1)

        return args

    def console_entry_point(self):
        """parse arguments, handle them, run the VaultRedirector"""
        args = self.parse_args(sys.argv[1:])
        if args.verbose == 1:
            set_log_info()
        elif args.verbose > 1:
            set_log_debug()

        redir = VaultRedirector(
            args.CONSUL_HOST_PORT,
            redir_to_https=args.https,
            redir_to_ip=args.redir_ip,
            log_disable=args.log_disable,
            poll_interval=args.poll_interval,
            bind_port=args.bind_port,
            check_id=args.checkid,
            key_path=args.key_path,
            cert_path=args.cert_path
        )
        redir.run()


def set_log_info():
    """set logger level to INFO"""
    set_log_level_format(logging.INFO,
                         '%(asctime)s %(levelname)s:%(name)s:%(message)s')


def set_log_debug():
    """set logger level to DEBUG, and debug-level output format"""
    set_log_level_format(
        logging.DEBUG,
        "%(asctime)s [%(levelname)s %(filename)s:%(lineno)s - "
        "%(name)s.%(funcName)s() ] %(message)s"
    )


def set_log_level_format(level, format):
    """
    Set logger level and format.

    :param level: logging level; see the :py:mod:`logging` constants.
    :type level: int
    :param format: logging formatter format string
    :type format: str
    """
    formatter = logging.Formatter(fmt=format)
    logger.handlers[0].setFormatter(formatter)
    logger.setLevel(level)


def console_entry_point():
    """
    console entry point - create a :py:class:`~.Runner` and call its
    :py:meth:`~.Runner.console_entry_point` method.
    """
    r = Runner()
    r.console_entry_point()


if __name__ == "__main__":
    console_entry_point()
