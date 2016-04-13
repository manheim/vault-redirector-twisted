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
import os
from vault_redirector.redirector import VaultRedirector, VaultRedirectorSite
from datetime import datetime
import signal
import vault_redirector.tests.testdata as testdata
from vault_redirector.version import _VERSION
from twisted._version import version as twisted_version
from twisted.internet import reactor, task
from twisted.internet.address import IPv4Address
from twisted.web import resource
from twisted.web.server import Request
from twisted.web._responses import NOT_FOUND, SERVICE_UNAVAILABLE
from twisted.web.http_headers import Headers
import pytest
import subprocess
import json

# https://code.google.com/p/mock/issues/detail?id=249
# py>=3.4 should use unittest.mock not the mock package on pypi
if (
        sys.version_info[0] < 3 or
        sys.version_info[0] == 3 and sys.version_info[1] < 4
):
    from mock import patch, call, Mock, DEFAULT
else:
    from unittest.mock import patch, call, Mock, DEFAULT

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
        assert cls.active_node_ip_port is None
        assert cls.consul_host_port == 'consul:123'
        assert cls.redir_https is False
        assert cls.redir_ip is False
        assert cls.log_enabled is True
        assert cls.poll_interval == 5.0
        assert cls.bind_port == 8080
        assert cls.check_id == 'service:vault'
        assert cls.consul_scheme == 'http'

    def test_init_nondefault(self):
        with patch('%s.setup_signal_handlers' % pb) as mock_setup_signals:
            with patch('%s.logger' % pbm) as mock_logger:
                with patch('%s.getpid' % pbm) as mock_getpid:
                    mock_getpid.return_value = 12345
                    cls = VaultRedirector(
                        'consul:123',
                        redir_to_https=True,
                        redir_to_ip=True,
                        log_disable=True,
                        poll_interval=1.234,
                        bind_port=1234,
                        check_id='foo:bar'
                    )
        assert mock_setup_signals.mock_calls == [call()]
        assert mock_logger.mock_calls == [
            call.warning(
                'Starting VaultRedirector with ALL LOGGING DISABLED; send '
                'SIGUSR1 to PID %d enable logging.',
                12345
            )
        ]
        assert cls.active_node_ip_port is None
        assert cls.consul_host_port == 'consul:123'
        assert cls.redir_https is True
        assert cls.redir_ip is True
        assert cls.log_enabled is False
        assert cls.poll_interval == 1.234
        assert cls.bind_port == 1234
        assert cls.check_id == 'foo:bar'
        assert cls.consul_scheme == 'https'

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

    def test_get_active_node(self):
        get_json = testdata.test_get_active_node
        with patch('%s.requests.get' % pbm) as mock_get:
            mock_get.return_value.json.return_value = get_json
            with patch('%s.logger' % pbm) as mock_logger:
                res = self.cls.get_active_node()
        url = 'http://consul:123/v1/health/service/vault'
        assert mock_get.mock_calls[0] == call(url)
        assert mock_logger.mock_calls == [
            call.debug('Polling active node from: %s', url),
            call.info('Got active node as: %s', 'node2:8200')
        ]
        assert res == 'node2:8200'

    def test_get_active_node_log_disabled(self):
        self.cls.log_enabled = False
        get_json = testdata.test_get_active_node
        with patch('%s.requests.get' % pbm) as mock_get:
            mock_get.return_value.json.return_value = get_json
            with patch('%s.logger' % pbm) as mock_logger:
                res = self.cls.get_active_node()
        url = 'http://consul:123/v1/health/service/vault'
        assert mock_get.mock_calls[0] == call(url)
        assert mock_logger.mock_calls == []
        assert res == 'node2:8200'

    def test_get_active_node_none(self):
        get_json = testdata.test_get_active_node_none
        with patch('%s.requests.get' % pbm) as mock_get:
            mock_get.return_value.json.return_value = get_json
            with patch('%s.logger' % pbm) as mock_logger:
                res = self.cls.get_active_node()
        url = 'http://consul:123/v1/health/service/vault'
        assert mock_get.mock_calls[0] == call(url)
        assert mock_logger.mock_calls == [
            call.debug('Polling active node from: %s', url),
            call.critical('NO vault services found with health check passing')
        ]
        assert res is None

    def test_get_active_node_none_log_disabled(self):
        self.cls.log_enabled = False
        get_json = testdata.test_get_active_node_none
        with patch('%s.requests.get' % pbm) as mock_get:
            mock_get.return_value.json.return_value = get_json
            with patch('%s.logger' % pbm) as mock_logger:
                res = self.cls.get_active_node()
        url = 'http://consul:123/v1/health/service/vault'
        assert mock_get.mock_calls[0] == call(url)
        assert mock_logger.mock_calls == []
        assert res is None

    def test_get_active_node_ip(self):
        get_json = testdata.test_get_active_node
        self.cls.redir_ip = True
        with patch('%s.requests.get' % pbm) as mock_get:
            mock_get.return_value.json.return_value = get_json
            with patch('%s.logger' % pbm) as mock_logger:
                res = self.cls.get_active_node()
        url = 'http://consul:123/v1/health/service/vault'
        assert mock_get.mock_calls[0] == call(url)
        assert mock_logger.mock_calls == [
            call.debug('Polling active node from: %s', url),
            call.info('Got active node as: %s', '172.17.0.4:8200')
        ]
        assert res == '172.17.0.4:8200'

    def test_update_active_node_same(self):
        self.cls.active_node_ip_port = 'a:b'
        with patch('%s.get_active_node' % pb) as mock_get:
            mock_get.return_value = 'a:b'
            with patch('%s.logger' % pbm) as mock_logger:
                self.cls.update_active_node()
        assert self.cls.active_node_ip_port == 'a:b'
        assert mock_logger.mock_calls == []

    def test_update_active_node_exception(self):
        def se_exc():
            raise RuntimeError('foo')

        self.cls.active_node_ip_port = 'a:b'
        with patch('%s.get_active_node' % pb) as mock_get:
            mock_get.side_effect = se_exc
            with patch('%s.logger' % pbm) as mock_logger:
                self.cls.update_active_node()
        assert self.cls.active_node_ip_port is None
        assert mock_logger.mock_calls == [
            call.exception('Exception encountered when polling active node'),
            call.warning('Active vault node changed from %s to %s',
                         'a:b', None)
        ]

    def test_update_active_node_different(self):
        self.cls.active_node_ip_port = 'a:b'
        with patch('%s.get_active_node' % pb) as mock_get:
            mock_get.return_value = 'c:d'
            with patch('%s.logger' % pbm) as mock_logger:
                self.cls.update_active_node()
        assert self.cls.active_node_ip_port == 'c:d'
        assert mock_logger.mock_calls == [
            call.warning('Active vault node changed from %s to %s',
                         'a:b', 'c:d')
        ]

    def test_listentcp(self):
        self.cls.reactor = Mock(spec_set=reactor)
        mock_site = Mock()
        with patch('%s.logger' % pbm) as mock_logger:
            self.cls.listentcp(mock_site)
        assert mock_logger.mock_calls == [
            call.warning('Setting TCP listener on port %d for HTTP requests',
                         8080)
        ]
        assert self.cls.reactor.mock_calls == [call.listenTCP(8080, mock_site)]

    def test_add_update_loop(self):
        self.cls.reactor = Mock(spec_set=reactor)
        with patch('%s.LoopingCall' % pbm) as mock_looping:
            with patch('%s.logger' % pbm) as mock_logger:
                self.cls.add_update_loop()
        assert mock_logger.mock_calls == [
            call.warning('Setting Consul poll interval to %s seconds',
                         5.0)
        ]
        assert mock_looping.mock_calls == [
            call(self.cls.update_active_node),
            call().start(5.0)
        ]

    def test_run(self):
        self.cls.reactor = Mock(spec_set=reactor)
        with patch.multiple(
            pbm,
            logger=DEFAULT,
            Site=DEFAULT,
            LoopingCall=DEFAULT,
            VaultRedirectorSite=DEFAULT
        ) as mod_mocks:
            with patch.multiple(
                pb,
                get_active_node=DEFAULT,
                run_reactor=DEFAULT,
                listentcp=DEFAULT,
                add_update_loop=DEFAULT
            ) as cls_mocks:
                cls_mocks['get_active_node'].return_value = 'consul:1234'
                self.cls.run()
        assert self.cls.active_node_ip_port == 'consul:1234'
        assert mod_mocks['logger'].mock_calls == [
            call.warning('Initial Vault active node: %s', 'consul:1234'),
            call.warning('Starting Twisted reactor (event loop)')
        ]
        assert mod_mocks['VaultRedirectorSite'].mock_calls == [call(self.cls)]
        assert mod_mocks['Site'].mock_calls == [
            call(mod_mocks['VaultRedirectorSite'].return_value)
        ]
        assert self.cls.reactor.mock_calls == []
        assert cls_mocks['run_reactor'].mock_calls == [call()]
        assert mod_mocks['LoopingCall'].mock_calls == []
        assert cls_mocks['listentcp'].mock_calls == [
            call(mod_mocks['Site'].return_value)
        ]
        assert cls_mocks['add_update_loop'].mock_calls == [call()]

    def test_run_error(self):
        self.cls.reactor = Mock(spec_set=reactor)
        with patch.multiple(
            pbm,
            logger=DEFAULT,
            Site=DEFAULT,
            LoopingCall=DEFAULT,
            VaultRedirectorSite=DEFAULT
        ) as mod_mocks:
            with patch.multiple(
                pb,
                get_active_node=DEFAULT,
                run_reactor=DEFAULT,
                listentcp=DEFAULT,
                add_update_loop=DEFAULT
            ) as cls_mocks:
                cls_mocks['get_active_node'].return_value = None
                with pytest.raises(SystemExit) as excinfo:
                    self.cls.run()
        assert excinfo.value.code == 3
        assert mod_mocks['logger'].mock_calls == [
            call.critical("ERROR: Could not get active vault node from "
                          "Consul. Exiting.")
        ]
        assert mod_mocks['VaultRedirectorSite'].mock_calls == []
        assert mod_mocks['Site'].mock_calls == []
        assert self.cls.reactor.mock_calls == []
        assert cls_mocks['run_reactor'].mock_calls == []
        assert mod_mocks['LoopingCall'].mock_calls == []

    def test_run_reactor(self):
        self.cls.reactor = Mock(spec_set=reactor)
        self.cls.run_reactor()
        assert self.cls.reactor.mock_calls == [call.run()]


class TestVaultRedirectorSite(object):

    def setup(self):
        self.mock_redir = Mock(spec_set=VaultRedirector)
        type(self.mock_redir).active_node_ip_port = 'consul:1234'
        type(self.mock_redir).log_enabled = True
        type(self.mock_redir).consul_scheme = 'http'
        self.cls = VaultRedirectorSite(self.mock_redir)

        # mock client request
        self.mock_request = Mock(spec_set=Request)
        type(self.mock_request).method = 'GET'
        client_addr = IPv4Address('TCP', '1.2.3.4', 12345)
        type(self.mock_request).client = client_addr
        type(self.mock_request).clientproto = 'HTTP/1.1'
        headers = Headers()
        headers.setRawHeaders('date', ['Mon, 11 Apr 2016 15:26:42 GMT'])
        headers.setRawHeaders('server', ['TwistedWeb/16.1.0'])
        type(self.mock_request).responseHeaders = headers
        type(self.mock_request).queued = 0

    def test_init(self):
        mock_redir = Mock(spec_set=VaultRedirector)
        cls = VaultRedirectorSite(mock_redir)
        assert cls.redirector == mock_redir
        assert cls.isLeaf is True

    def test_getChildWithDefault(self):
        res = self.cls.getChildWithDefault(None, None)
        assert isinstance(res, resource.ErrorPage)
        assert res.code == NOT_FOUND
        assert res.brief == 'No Such Resource'
        assert res.detail == 'No Such Resource'

    def test_render(self):
        expected_location = 'http://consul:1234/foo/bar'
        expected_server = 'vault-redirector/%s/TwistedWeb/16.1.0' % _VERSION
        type(self.mock_request).uri = '/foo/bar'
        type(self.mock_request).path = '/foo/bar'
        self.mock_request.reset_mock()

        with patch('%s.logger' % pbm) as mock_logger:
            resp = self.cls.render(self.mock_request)
        assert self.mock_request.mock_calls == [
            call.setHeader('server', expected_server),
            call.setResponseCode(307),
            call.setHeader('Location', expected_location),
            call.setHeader("Content-Type", "text/html; charset=UTF-8")
        ]
        assert resp == ''
        assert mock_logger.mock_calls == [
            call.info('RESPOND 307 to %s for %s%s request for %s from %s:%s',
                      expected_location, '', 'GET', '/foo/bar', '1.2.3.4',
                      12345)
        ]

    def test_render_queued(self):
        expected_location = 'http://consul:1234/foo/bar'
        expected_server = 'vault-redirector/%s/TwistedWeb/16.1.0' % _VERSION
        type(self.mock_request).uri = '/foo/bar'
        type(self.mock_request).path = '/foo/bar'
        type(self.mock_request).queued = 1
        self.mock_request.reset_mock()

        with patch('%s.logger' % pbm) as mock_logger:
            resp = self.cls.render(self.mock_request)
        assert self.mock_request.mock_calls == [
            call.setHeader('server', expected_server),
            call.setResponseCode(307),
            call.setHeader('Location', expected_location),
            call.setHeader("Content-Type", "text/html; charset=UTF-8")
        ]
        assert resp == ''
        assert mock_logger.mock_calls == [
            call.info('RESPOND 307 to %s for %s%s request for %s from %s:%s',
                      expected_location, 'QUEUED ', 'GET', '/foo/bar',
                      '1.2.3.4', 12345)
        ]

    def test_render_log_disabled(self):
        expected_location = 'http://consul:1234/foo/bar'
        expected_server = 'vault-redirector/%s/TwistedWeb/16.1.0' % _VERSION
        type(self.mock_request).uri = '/foo/bar'
        type(self.mock_request).path = '/foo/bar'
        self.mock_request.reset_mock()
        type(self.mock_redir).log_enabled = False

        with patch('%s.logger' % pbm) as mock_logger:
            resp = self.cls.render(self.mock_request)
        assert self.mock_request.mock_calls == [
            call.setHeader('server', expected_server),
            call.setResponseCode(307),
            call.setHeader('Location', expected_location),
            call.setHeader("Content-Type", "text/html; charset=UTF-8")
        ]
        assert resp == ''
        assert mock_logger.mock_calls == []

    def test_render_503(self):
        type(self.mock_redir).active_node_ip_port = None
        expected_server = 'vault-redirector/%s/TwistedWeb/16.1.0' % _VERSION
        type(self.mock_request).uri = '/foo/bar'
        type(self.mock_request).path = '/foo/bar'
        self.mock_request.reset_mock()

        with patch('%s.logger' % pbm) as mock_logger:
            resp = self.cls.render(self.mock_request)
        assert self.mock_request.mock_calls == [
            call.setHeader('server', expected_server)
        ]
        assert isinstance(resp, resource.ErrorPage)
        assert resp.code == SERVICE_UNAVAILABLE
        assert resp.brief == 'No Active Node'
        assert resp.detail == 'No active Vault leader could be determined ' \
                              'from Consul API'
        assert mock_logger.mock_calls == [
            call.warning('RESPOND 503 for %s%s request for %s from %s:%s',
                         '', 'GET', '/foo/bar', '1.2.3.4', 12345)
        ]

    def test_render_503_queued(self):
        type(self.mock_redir).active_node_ip_port = None
        expected_server = 'vault-redirector/%s/TwistedWeb/16.1.0' % _VERSION
        type(self.mock_request).uri = '/foo/bar'
        type(self.mock_request).path = '/foo/bar'
        type(self.mock_request).queued = 1
        self.mock_request.reset_mock()

        with patch('%s.logger' % pbm) as mock_logger:
            resp = self.cls.render(self.mock_request)
        assert self.mock_request.mock_calls == [
            call.setHeader('server', expected_server)
        ]
        assert isinstance(resp, resource.ErrorPage)
        assert resp.code == SERVICE_UNAVAILABLE
        assert resp.brief == 'No Active Node'
        assert resp.detail == 'No active Vault leader could be determined ' \
                              'from Consul API'
        assert mock_logger.mock_calls == [
            call.warning('RESPOND 503 for %s%s request for %s from %s:%s',
                         'QUEUED ', 'GET', '/foo/bar', '1.2.3.4', 12345)
        ]

    def test_render_503_log_disabled(self):
        type(self.mock_redir).active_node_ip_port = None
        expected_server = 'vault-redirector/%s/TwistedWeb/16.1.0' % _VERSION
        type(self.mock_request).uri = '/foo/bar'
        type(self.mock_request).path = '/foo/bar'
        self.mock_request.reset_mock()
        type(self.mock_redir).log_enabled = False

        with patch('%s.logger' % pbm) as mock_logger:
            resp = self.cls.render(self.mock_request)
        assert self.mock_request.mock_calls == [
            call.setHeader('server', expected_server)
        ]
        assert isinstance(resp, resource.ErrorPage)
        assert resp.code == SERVICE_UNAVAILABLE
        assert resp.brief == 'No Active Node'
        assert resp.detail == 'No active Vault leader could be determined ' \
                              'from Consul API'
        assert mock_logger.mock_calls == []


class TestVaultRedirectorAcceptance(object):

    def setup(self):
        """instantiate class and set some attributes on this class"""
        self.response = None
        self.poller = None
        self.poller_check_task = None
        self.update_active_called = False
        self.cls = VaultRedirector('consul:1234', poll_interval=2.0)

    def se_run_reactor(self):
        """this will cause the reactor to run for 10 seconds only"""
        print(datetime.now().isoformat(), 'call se_run_reactor')
        self.cls.reactor.callLater(10.0, self.stop_reactor)
        self.cls.reactor.run()
        print(datetime.now().isoformat(), 'se_run_reactor done')

    def stop_reactor(self, signum=None, frame=None):
        print(datetime.now().isoformat(), 'stopping reactor')
        self.cls.reactor.stop()

    def se_requester(self):
        """
        While the reactor is polling, we can't make any requests. So have the
        reactor itself make the request and store the result.
        """
        print(datetime.now().isoformat(), 'requester called; spawning process')
        # since Python is single-threaded and Twisted is just event-based,
        # we can't do a request and run the redirector from the same script.
        # Best choice is to used popen to run an external script to do the
        # redirect.
        url = 'http://127.0.0.1:%d/bar/baz' % self.cls.bind_port
        path = os.path.join(os.path.dirname(__file__), 'requester.py')
        self.poller = subprocess.Popen(
            [sys.executable, path, url],
            stdout=subprocess.PIPE,
            universal_newlines=True
        )
        # run a poller loop to check for process stop and get results
        self.poller_check_task = task.LoopingCall(self.check_request)
        self.poller_check_task.clock = self.cls.reactor
        self.poller_check_task.start(0.5)
        print(datetime.now().isoformat(), 'poller_check_task started')

    def check_request(self):
        """
        check if the self.poller process has finished; if so, handle results
        and stop the poller_check_task. If update_active has also already been
        called, stop the reactor.
        """
        print(datetime.now().isoformat(), 'check_request called')
        if self.poller.poll() is None:
            print(datetime.now().isoformat(), 'poller process still running')
            return
        # stop the looping task
        self.poller_check_task.stop()
        assert self.poller.returncode == 0
        out, err = self.poller.communicate()
        self.response = out.strip()
        # on python3, this will be binary
        if not isinstance(self.response, str):
            self.response = self.response.decode('utf-8')
        print(datetime.now().isoformat(), 'check_request done')
        if self.update_active_called:
            self.stop_reactor()

    def se_update_active(self):
        """
        Mocked update_active_node()
        - set class attribute on this class stating it was called
        - update ``self.cls.active_node_ip_port``
        - if we've also already done the request, stop the reactor
        """
        print(datetime.now().isoformat(), 'update_active called')
        self.update_active_called = True
        self.cls.active_node_ip_port = 'bar:5678'
        if self.response is not None:
            self.stop_reactor()

    def test_acceptance(self):
        print(datetime.now().isoformat(), 'starting acceptance test')
        with patch.multiple(
            pb,
            get_active_node=DEFAULT,
            run_reactor=DEFAULT,
            update_active_node=DEFAULT
        ) as cls_mocks:
            # setup some return values
            cls_mocks['run_reactor'].side_effect = self.se_run_reactor
            cls_mocks['get_active_node'].return_value = 'foo:1234'
            cls_mocks['update_active_node'].side_effect = self.se_update_active
            # instantiate class
            self.cls = VaultRedirector('consul:1234')
            # make sure active is None (starting state)
            assert self.cls.active_node_ip_port is None
            self.cls.log_enabled = True
            # setup an async task to make the HTTP request
            self.cls.reactor.callLater(2.0, self.se_requester)
            # do this in case the callLater for self.stop_reactor fails...
            signal.signal(signal.SIGALRM, self.stop_reactor)
            signal.alarm(20)  # send SIGALRM in 20 seconds, to stop runaway loop
            self.cls.run()
            signal.alarm(0)  # disable SIGALRM
        assert self.cls.active_node_ip_port == 'bar:5678'  # from update_active
        assert self.update_active_called is True
        resp = json.loads(self.response)
        assert resp['headers'][
                   'Server'] == "vault-redirector/%s/TwistedWeb/%s" %(
            _VERSION, twisted_version.short()
        )
        assert resp['headers']['Location'] == 'http://bar:5678/bar/baz'
        assert resp['status_code'] == 307
        assert cls_mocks['update_active_node'].mock_calls[0] == call()
        assert cls_mocks['run_reactor'].mock_calls == [call()]
        assert cls_mocks['get_active_node'].mock_calls == [call()]
