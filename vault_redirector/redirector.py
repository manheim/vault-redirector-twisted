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

import sys
import logging
import signal
import json
from os import getpid, access, R_OK
import requests
from twisted.web import resource
from twisted.web.server import Site
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.web._responses import NOT_FOUND, SERVICE_UNAVAILABLE, OK
from vault_redirector.version import _VERSION, _PROJECT_URL

try:  # nocoverage
    from OpenSSL import SSL  # pragma: no flakes
    from pem.twisted import certificateOptionsFromFiles
    HAVE_PYOPENSSL = True
except ImportError:
    HAVE_PYOPENSSL = False

logger = logging.getLogger()


class VaultRedirector(object):

    def __init__(self, consul_host_port,
                 redir_to_https=False, redir_to_ip=False, log_disable=False,
                 poll_interval=5.0, bind_port=8080, check_id='service:vault',
                 key_path=None, cert_path=None):
        """
        Initialize the redirector service.

        :param consul_host_port: Consul host/IP and port in ``host:port`` form
        :type consul_host_port: str
        :param redir_to_https: Redirect to HTTPS if True, otherwise HTTP
        :type redir_to_https: bool
        :param redir_to_ip: Redirect to IP if True, otherwise node name
        :type redir_to_ip: bool
        :param log_disable: If True, do not fire ANY :py:mod:`logging` module
          calls from this class after initial setup; ignore them all. This can
          be changed at runtime via signals.
        :type log_disable: bool
        :param poll_interval: interval in seconds to poll Consul service health
        :type poll_interval: float
        :param bind_port: port number to bind to / listen on
        :type bind_port: int
        :param check_id: Consul health check ID to use for Vault
        :type check_id: str
        :param key_path: path to TLS key to use on listener; this param enables
          TLS and must be used in combination with ``cert_path``
        :type key_path: str
        :param cert_path: path to TLS cert to use on listener; this param
          enables TLS and must be used in combination with ``key_path``
        :type cert_path: str
        """
        self.active_node_ip_port = None
        self.consul_host_port = consul_host_port
        self.redir_https = redir_to_https
        self.consul_scheme = 'http'
        if self.redir_https:
            self.consul_scheme = 'https'
        self.redir_ip = redir_to_ip
        self.log_enabled = not log_disable
        self.poll_interval = poll_interval
        self.bind_port = bind_port
        self.check_id = check_id
        # setup signal handlers for logging enable/disable
        self.setup_signal_handlers()
        if not self.log_enabled:
            # be sure to warn the user of how to enable logging
            logger.warning('Starting VaultRedirector with ALL LOGGING '
                           'DISABLED; send SIGUSR1 to PID %d enable logging.',
                           getpid())
        # per the Twisted API docs, "New application code should prefer to pass
        # and accept the reactor as a parameter where it is needed, rather than
        # relying on being able to import this module to get a reference.
        self.use_tls = False
        self.reactor = reactor
        self.tls_factory = None
        if (cert_path is not None and key_path is None) or (
            cert_path is None and key_path is not None
        ):
            raise RuntimeError('VaultRedirector class constructor must either '
                               'receive both cert_path and key_path, '
                               'or neither.')
        if cert_path is not None and key_path is not None:
            self.cert_path = cert_path
            self.key_path = key_path
            self.tls_factory = self.get_tls_factory()

    def get_tls_factory(self):
        """
        If we have paths to a TLS certificate and key, check that we're ready
        to actually use them:

        * TLS-related imports worked
        * cert and key are readable
        * cert and key can be loaded

        Then return a SSL contextFactory instance to use for the server.

        :returns: SSL contextFactory for our server to use
        :rtype: :py:class:`twisted.internet.ssl.CertificateOptions`
        """
        if not access(self.cert_path, R_OK):
            raise RuntimeError('Error: cert file at %s is not '
                               'readable' % self.cert_path)
        if not access(self.key_path, R_OK):
            raise RuntimeError('Error: key file at %s is not '
                               'readable' % self.key_path)
        if not HAVE_PYOPENSSL:
            raise RuntimeError('Error: running with TLS (cert and key) requires'
                               ' pyOpenSSL, but it does not appear to be '
                               'installed. Please "pip install pyOpenSSL".')
        # check certs are readable
        cf = certificateOptionsFromFiles(self.key_path, self.cert_path)
        return cf

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

    def get_active_node(self):
        """
        GET the Consul URL for the 'vault' service health check, parse the JSON
        reply, and return either the active node in (name|ip):port form, or
        None if no active node can be found.

        :return: active node in ``(name|ip):port`` form (str) or None
        """
        url = 'http://%s/v1/health/service/vault' % self.consul_host_port
        # parse the health check results and find the one that's passing
        if self.log_enabled:
            logger.debug('Polling active node from: %s', url)
        r = requests.get(url)
        # return the current leader address
        for node in r.json():
            for check in node['Checks']:
                if check['CheckID'] != self.check_id:
                    continue
                if check['Status'] != 'passing':
                    continue
                port = node['Service']['Port']
                n = "%s:%d" % (node['Node']['Node'], port)
                if self.redir_ip:
                    n = "%s:%d" % (node['Node']['Address'], port)
                if self.log_enabled:
                    logger.info("Got active node as: %s", n)
                return n
        if self.log_enabled:
            logger.critical('NO vault services found with health check passing')
        return None

    def update_active_node(self):
        """
        Run :py:meth:`~.get_active_node` and update ``self.active_node_ip_port``
        to its value. If it raised an Exception, log the exception and set
        ``self.active_node_ip_port`` to None.
        """
        try:
            newnode = self.get_active_node()
        except Exception:
            logger.exception('Exception encountered when polling active node')
            # we have a choice here whether to keep serving the old active
            # node, or start serving 503s. Might as well serve the old one, in
            # case the error is with Consul or intermittent. If the node is
            # really down, the client will end up with an error anyway...
            newnode = None
        if self.log_enabled and newnode != self.active_node_ip_port:
            logger.warning("Active vault node changed from %s to %s",
                           self.active_node_ip_port, newnode)
            self.active_node_ip_port = newnode

    def run_reactor(self):
        """Method to run the Twisted reactor; mock point for testing"""
        self.reactor.run()

    def listentcp(self, site):
        """
        Setup TCP listener for the Site; helper method for testing

        :param site: Site to serve
        :type site: :py:class:`~.VaultRedirectorSite`
        """
        logger.warning('Setting TCP listener on port %d for HTTP requests',
                       self.bind_port)
        self.reactor.listenTCP(self.bind_port, site)

    def listentls(self, site):
        """
        Setup TLS listener for the Site; helper method for testing

        :param site: Site to serve
        :type site: :py:class:`~.VaultRedirectorSite`
        """
        logger.warning('Setting TCP TLS listener on port %d for HTTPS requests',
                       self.bind_port)
        self.reactor.listenSSL(self.bind_port, site, self.tls_factory)

    def add_update_loop(self):
        """
        Setup the LoopingCall to poll Consul every ``self.poll_interval``;
        helper for testing.
        """
        l = LoopingCall(self.update_active_node)
        l.clock = self.reactor
        logger.warning('Setting Consul poll interval to %s seconds',
                       self.poll_interval)
        l.start(self.poll_interval)

    def run(self):
        """setup the site, start listening on port, setup the looping call to
        :py:meth:`~.update_active_node` every ``self.poll_interval`` seconds,
        and start the Twisted reactor"""
        # get the active node before we start anything...
        self.active_node_ip_port = self.get_active_node()
        if self.active_node_ip_port is None:
            logger.critical("ERROR: Could not get active vault node from "
                            "Consul. Exiting.")
            raise SystemExit(3)
        logger.warning("Initial Vault active node: %s",
                       self.active_node_ip_port)
        site = Site(VaultRedirectorSite(self))
        # setup our HTTP(S) listener
        if self.tls_factory is not None:
            self.listentls(site)
        else:
            self.listentcp(site)
        # setup the update_active_node poll every POLL_INTERVAL seconds
        self.add_update_loop()
        logger.warning('Starting Twisted reactor (event loop)')
        self.run_reactor()


class VaultRedirectorSite(object):
    """
    Unfortunately :py:class:`twisted.web.resource.Resource` is an old-style
    class, so we can't easily subclass it and override its ``__init__``. So,
    we implement the :py:class:`twisted.web.resource.IResource` interface
    ourselves.
    """

    isLeaf = True

    def __init__(self, redirector):
        """

        :param redirector: VaultRedirector instance
        :type redirector: :py:class:`~.VaultRedirector` instance
        """
        self.redirector = redirector

    def status_response(self):
        s = json.dumps({
            'healthy': True,
            'application': 'vault-redirector',
            'source': _PROJECT_URL,
            'version': _VERSION,
            'consul_host_port': self.redirector.consul_host_port,
            'active_vault': self.redirector.active_node_ip_port
        })
        return s

    def getChildWithDefault(self, name, request):
        """
        This should never be called; it's simply required to implement the
        :py:class:`twisted.web.resource.IResource` interface. Just returns
        a 404.

        See: :py:meth:`twisted.web.resource.IResource.getChildWithDefault`
        """
        return resource.ErrorPage(NOT_FOUND, "No Such Resource",
                                  "No Such Resource")

    def make_response(self, s):
        """python 3+ needs a binary response; create one"""
        if sys.version_info[0] < 3:
            return s
        return s.encode('utf-8')  # nocoverage - unreachable under py2

    def healthcheck(self, request):
        """
        Generate and return a healthcheck response.

        :param request: incoming HTTP request
        :type request: :py:class:`twisted.web.server.Request`
        :return: JSON response data string
        :rtype: str
        """
        statuscode = OK
        msg = self.make_response('OK')
        if self.redirector.active_node_ip_port is None:
            statuscode = SERVICE_UNAVAILABLE
            msg = self.make_response('No Active Vault')
        request.setResponseCode(statuscode, message=msg)
        request.setHeader("Content-Type", 'application/json')
        # log if logging is enabled
        if self.redirector.log_enabled:
            queued = ''
            if request.queued:
                queued = 'QUEUED '
            logger.info('RESPOND %d for %s%s request for '
                        '/vault-redirector-health from %s:%s',
                        statuscode, queued, str(request.method),
                        request.client.host, request.client.port)
        return self.make_response(self.status_response())

    def render(self, request):
        """
        Render the response to the given request. This simply gets the current
        active vault node from ``self.redirector`` (our instance of
        :py:class:`~.VaultRedirector`) and returns a 307 Temporary Redirect
        to the same path as the request, on that active node.

        The ``request`` param is an instance of
        :py:class:`twisted.web.server.Request`, which implements
        :py:class:`twisted.web.iweb.IRequest` and inherits from
        :py:class:`twisted.web.http.Request`

        The return value is meaningless. We simply set a response code and
        headers on the ``request`` parameter.

        If we were unable to retrieve the current active Vault node from the
        Consul API, return a 503 error response. This is the same code that
        Vault uses when it is down for maintenance or sealed.

        :param request: incoming HTTP request
        :type request: :py:class:`twisted.web.server.Request`
        :return: empty string (None)
        :rtype: str
        """
        path = request.uri
        # python3 will get a byte string here
        if not isinstance(path, str):  # nocoverage - py3 only
            path = path.decode('utf-8')
        # find the original Twisted server header
        twisted_server = request.responseHeaders.getRawHeaders(
            'server', 'Twisted'
        )[0]
        request.setHeader('server',
                          'vault-redirector/%s/%s' % (_VERSION, twisted_server))
        # handle health check request
        if path == '/vault-redirector-health':
            return self.healthcheck(request)
        # if we don't know what the active Vault instance is, respond 503
        if self.redirector.active_node_ip_port is None:
            if self.redirector.log_enabled:
                queued = ''
                if request.queued:
                    queued = 'QUEUED '
                logger.warning('RESPOND 503 for %s%s request for %s from %s:%s',
                               queued, str(request.method), path,
                               request.client.host, request.client.port)
            return resource.ErrorPage(
                SERVICE_UNAVAILABLE,
                "No Active Node",
                "No active Vault leader could be determined from Consul API"
            )
        # if we DO know what the active Vault node is, redirect
        # figure out redirect path
        redir_to = '%s://%s%s' % (
            self.redirector.consul_scheme,
            self.redirector.active_node_ip_port,
            path
        )
        # log if logging is enabled
        if self.redirector.log_enabled:
            queued = ''
            if request.queued:
                queued = 'QUEUED '
            logger.info('RESPOND 307 to %s for %s%s request for %s from %s:%s',
                        redir_to, queued, str(request.method), path,
                        request.client.host, request.client.port)
        # send the redirect
        request.setResponseCode(307)
        request.setHeader("Location", redir_to)
        request.setHeader("Content-Type", "text/html; charset=UTF-8")
        return self.make_response('')
