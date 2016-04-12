vault-redirector-twisted
========================

Python/Twisted application to redirect `Hashicorp Vault <https://www.vaultproject.io/>`_ client requests to the active node in a HA cluster.

**NOTE:** My initial plan was to implement this in Go. My Go knowledge is severely lacking, and the performance of Python/Twisted at 1,000 requests per second is within 25% of the Go variant. Please consider this package to be temporary, until work on the Go version (`https://github.com/manheim/vault-redirector <https://github.com/manheim/vault-redirector>`_) continues.

Status
------

This application is currently very young. Please ensure it meets your needs before using it in production.

Purpose
-------

There's a bit of a gap in usability of `Vault <https://www.vaultproject.io/>`_ in a `High Availability <https://www.vaultproject.io/docs/concepts/ha.html>`_ mode, at least in AWS:

* Vault's HA architecture is based on an active/standby model; only one server can be active at a time, and any others are standby. Standby servers respond to all API requests with a 307 Temporary Redirect to the Active server, but can only do this if they're unsealed (in the end of the `HA docs <https://www.vaultproject.io/docs/internals/high-availability.html>`_: "It is important to note that only unsealed servers act as a standby. If a server is still in the sealed state, then it cannot act as a standby as it would be unable to serve any requests should the active server fail.").
* HashiCorp recommends managing infrastructure individually, i.e. not in an auto-scaling group. In EC2, if you want to run Consul on the same nodes, this is an absolute requirement as Consul requires static IP addresses in order for disaster recovery to work without downtime and manual changes.

As a result, we're left with a conundrum:

1. We can't put Vault behind an Elastic Load Balancer, because that would cause all API requests to appear to have the ELB's source IP address. Not only does this render any of the IP- or subnet-based authorization methods unusable, but it also means we lose client IPs in the audit logs (which is likely a deal-breaker for anyone concerned with security).
2. The only remaining option for HA, at least in AWS, is to use Route53 round-robin DNS records that have the IPs of all of the cluster members. This poses a problem because if one node in an N-node cluster is either offline or sealed, approximately 1/N of all client requests will be directed to that node and fail.

While it would be good for all clients to automatically retry these requests, it appears that most client libraries (and even the ``vault`` command line client) do not currently support this. While retry logic would certainly be good to implement in any case, it adds latency to retrieving secrets (in the common case where the cluster is reachable, but some nodes are down) and also does not account for possible DNS caching issues. Furthermore, we're providing Vault as a service to our organization; relying on retries would mean either adding retry logic to every Vault client library and getting those changes merged, or deviating from our plan of "here's your credentials and endpoint, see the upstream docs for your language's client library."

The best solution to this problem would be for `Vault issue #799 <https://github.com/hashicorp/vault/issues/799>`_, a request to add `PROXY Protocol <http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt>`_ support to Vault, to be completed. Both `AWS ELBs <http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/enable-proxy-protocol.html>`_ and HAProxy support this, and it would alleviate issue #1 above, allowing us to run Vault behind a load balancer but still have access to the original client IP address.

This small service is intended to provide an interim workaround until that solution is implemented.

Functionality
-------------

We take advantage of Vault's 307 redirects (and the assumption that any protocol-compliant client library will honor them). Instead of connecting directly to the Vault service, clients connect to a load-balanced daemon running on the Vault nodes. This daemon asynchronously polls Consul for the health status of the Vault instances, and therefore knows the currently-active Vault instance at all times. All incoming HTTP(S) requests are simply 307 redirected to the active instance. As this service can safely be load balanced, it will tolerate failed nodes better than round-robin DNS. Since it redirects the client to the active node, the client's IP address will be properly seen by Vault.

Requirements
------------

1. Python >= 2.7, 3.3+ with ``pip``
2. `virtualenv <https://virtualenv.pypa.io/en/latest/>`_ is recommended.
3. The `requests <http://docs.python-requests.org/en/master/>`_ library (will be installed automatically via ``pip``).
4. `Consul <https://www.consul.io/>`_ running and configured with service checks for Vault (see below)

**Note** that Twisted does not yet (April 2016) have full Python 3 compatibility. Per
`Twisted's python3 plan <https://twistedmatrix.com/trac/wiki/Plan/Python3#Details>`_
it appears that all modules we use are done, and both unit and manual tests under Python
3.5 work. Please note, however, that Twisted is not officially supported on Python3.

Consul Service Checks
++++++++++++++++++++++

In order to determine the active Vault instance, ``vault-redirector`` requires that Consul be running and monitoring the health of all Vault instances. Redirection can be to either the IP address or Consul node name running the active service.

Here is example of the `Consul service definition <https://www.consul.io/docs/agent/services.html>`_ that we use (note we're running Vault with TLS); you can override the service name via command-line arguments:

.. code-block:: json

    {
      "service":{
        "name": "vault",
        "tags": ["secrets"],
        "port": 8200,
        "check": {
          "id": "api",
          "name": "HTTPS API check on port 8200",
          "http": "https://127.0.0.1:8200/v1/sys/health",
          "interval": "5s",
          "timeout" : "2s"
        }
      }
    }

**Please Note** that vault-redirector will use either the Consul node name or node address (IP) to redirect to; they should be set correctly to what clients will connect to.

Installation
------------

We recommend installing inside an isolated virtualenv. If you don't want to do that, please adjust the instructions as required:

1. ``virtualenv vault``
2. ``source vault/bin/activate``
3. ``pip install vault-redirector``

Usage
-----

Command Line Usage
++++++++++++++++++

All options and configuration are passed in via command-line options.

.. code-block:: console

    jantman@exodus$ vault-redirector -h
    usage: vault-redirector [-h] [-v] [-l] [-V] [-S] [-I] [-p POLL_INTERVAL]
                            [-P BIND_PORT] [-c CHECKID]
                            CONSUL_HOST_PORT

    Python/Twisted application to redirect Hashicorp Vault client requests to the
    active node in a HA cluster

    positional arguments:
      CONSUL_HOST_PORT      Consul address in host:port form

    optional arguments:
      -h, --help            show this help message and exit
      -v, --verbose         verbose output. specify twice for debug-level output.
                            See also -l|--log-enable
      -l, --log-disable     If specified, disable ALL logging after initial setup.
                            This can be changed at runtime via signals
      -V, --version         show program's version number and exit
      -S, --https           Redirect to HTTPS scheme instead of plain HTTP.
      -I, --ip              redirect to active node IP instead of name
      -p POLL_INTERVAL, --poll-interval POLL_INTERVAL
                            Consul service health poll interval in seconds
                            (default 5.0)
      -P BIND_PORT, --port BIND_PORT
                            Port number to listen on (default 8080)
      -c CHECKID, --checkid CHECKID
                            Consul service CheckID for Vault (default:
                            "service:vault"

By default, ``vault-redirector`` will redirect clients to the hostname (Consul
health check **node name**) of the active Vault node, over plain HTTP. This can
be changed via the ``-I | --ip`` and ``-S | --https`` options.

Running as a Daemon / Service
+++++++++++++++++++++++++++++

For anything other than testing, ``vault-redirector`` should be run as a system
service. There is no built-in daemonizing support; this is left up to your
operating system.

Here is an example `systemd <https://www.freedesktop.org/wiki/Software/systemd/>`_
service unit file for ``vault-redirector``:

TODO: sample unit file

Logging and Debugging
---------------------

Python's logging framework can impose a slight performance penalty even for messages
which are below the level set to be displayed (simple testing reports 10x execution
time for logging to a level below what's set, vs guarding the log statements with
a conditional). As a result, in addition to Python's normal logging verbosity
levels, all logging statements after initial setup are guarded by a global
"logging enabled" boolean; if logging is not enabled, the calls to Python's
logging framework will never be made. This behavior can be enabled by running
the process with the ``-l`` or ``--log-disable`` options (which is the
recommended production configuration).

Note that this functionality is completely separate from the logging module's
levels, which are controlled by the ``-v`` / ``-vv`` options (and are not currently
changeable at runtime).

At any time, logging can be enabled by sending SIGUSR1 to the process, or disabled
by sending SIGUSR2 to the process.

Support
-------

Please open any issues or feature requests in the `manheim/vault-redirector-twisted GitHub issue tracker<https://github.com/manheim/vault-redirector-twisted/issues>`_  They will be dealt with as time allows. Please include as much detail as possible, including your version of ``vault-redirector`` and the Python version and OS/distribution it's running on, as well as the command line arguments used when running it. Debug-level logs will likely be very helpful.

Development
-----------

Pull requests are welcome. Please cut them against the ``master`` branch of the `manheim/vault-redirector-twisted <https://github.com/manheim/vault-redirector-twisted>`_ repository. It is expected that test coverage increase or stay the same, and that all tests pass.

Testing
-------

Testing is accomplished via `pytest <http://pytest.org/latest/>`_ and
`tox <http://tox.readthedocs.org/en/latest/>`_. By default tests will be run
for Python 2.7, 3.3, 3.4. 3.5 and the documentation. To run tests locally, use ``tox`` per its documentation (i.e. ``tox -e py27`` to run the Python 2.7 test suite).

Automated testing is accomplished via TravisCI.

Release Process
---------------

TODO.

License
-------

vault-redirector is licensed under the MIT license; see ``LICENSE`` for the text of the license.
