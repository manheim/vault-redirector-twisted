Changelog
=========

0.2.0 (2016-06-15)
------------------

* Breaking change to how the active node is determined from Consul. Prior to
  this version, we looked for a 'vault' service with a health check named
  'service:vault' (configurable via the VaultRedirector class constructor,
  or the ``-c | --checkid`` command line argument) that was passing. With
  Vault 0.6.0's automatic registration of service and health checks in Consul,
  this needs to change. The logic to find the active node now looks for a node
  in Consul that has the 'vault' service and a tag of 'active'.

0.1.1 (2016-04-21)
------------------

* `issue #2 <https://github.com/manheim/vault-redirector-twisted/issues/2>`_
  * add timestamp of last active Vault update to health status output as ``last_consul_poll`` key
  * fix critical issue where active node did not update if logging was disabled

0.1.0 (2016-04-15)
------------------

* initial release
