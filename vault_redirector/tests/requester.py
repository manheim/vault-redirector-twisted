"""
redirector/tests/requester.py

HELPER SCRIPT for vault_redirector/tests/test_redirector.py
  TestVaultRedirectorAcceptance::test_acceptance

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
import requests
import json


def runit(base_url, paths):
    """
    Given a list of URLs, GET each of them with :py:meth:`requests.get` (not
    following redirects), save the headers, body text and status code, and then
    print to STDOUT a JSON hash/dict with all of the results.

    :param urls:
    :return:
    """
    result = {}
    for path in paths:
        url = base_url + path
        try:
            r = requests.get(url, allow_redirects=False)
            result[path] = {
                'headers': dict(r.headers.items()),
                'text': r.text,
                'status_code': r.status_code,
                'exception': None
            }
        except Exception as ex:
            result[path] = {'exception': str(ex)}
    print(json.dumps(result))

if __name__ == "__main__":
    runit(sys.argv[1], sys.argv[2:])
