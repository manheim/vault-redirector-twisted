"""
redirector/tests/testdata.py

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

from copy import deepcopy

test_get_active_node = [
    {
        'Checks': [
            {
                'CheckID': 'serfHealth',
                'CreateIndex': 3,
                'ModifyIndex': 3,
                'Name': 'Serf Health Status',
                'Node': 'node0',
                'Notes': '',
                'Output': 'Agent alive and reachable',
                'ServiceID': '',
                'ServiceName': '',
                'Status': 'passing'
            },
            {
                'CheckID': 'service:vault',
                'CreateIndex': 7,
                'ModifyIndex': 7,
                'Name': "Service 'vault' check",
                'Node': 'node0',
                'Notes': '',
                'Output': '',
                'ServiceID': 'vault',
                'ServiceName': 'vault',
                'Status': 'warning'
            }
        ],
        'Node': {
            'Address': '172.17.0.2',
            'CreateIndex': 3,
            'ModifyIndex': 7,
            'Node': 'node0'
        },
        'Service': {
            'Address': '',
            'CreateIndex': 7,
            'EnableTagOverride': False,
            'ID': 'vault',
            'ModifyIndex': 7,
            'Port': 8200,
            'Service': 'vault',
            'Tags': ['secrets']
        }
    },
    {
        'Checks': [
            {
                'CheckID': 'serfHealth',
                'CreateIndex': 5,
                'ModifyIndex': 5,
                'Name': 'Serf Health Status',
                'Node': 'node1',
                'Notes': '',
                'Output': 'Agent alive and reachable',
                'ServiceID': '',
                'ServiceName': '',
                'Status': 'passing'
            },
            {
                'CheckID': 'service:vault',
                'CreateIndex': 17,
                'ModifyIndex': 17,
                'Name': "Service 'vault' check",
                'Node': 'node1',
                'Notes': '',
                'Output': '',
                'ServiceID': 'vault',
                'ServiceName': 'vault',
                'Status': 'warning'
            }
        ],
        'Node': {
            'Address': '172.17.0.3',
            'CreateIndex': 5,
            'ModifyIndex': 20,
            'Node': 'node1'
        },
        'Service': {
            'Address': '',
            'CreateIndex': 17,
            'EnableTagOverride': False,
            'ID': 'vault',
            'ModifyIndex': 17,
            'Port': 8200,
            'Service': 'vault',
            'Tags': ['secrets']
        }
    },
    {
        'Checks': [
            {
                'CheckID': 'serfHealth',
                'CreateIndex': 9,
                'ModifyIndex': 9,
                'Name': 'Serf Health Status',
                'Node': 'node2',
                'Notes': '',
                'Output': 'Agent alive and reachable',
                'ServiceID': '',
                'ServiceName': '',
                'Status': 'passing'
            },
            {
                'CheckID': 'service:vault',
                'CreateIndex': 21,
                'ModifyIndex': 21,
                'Name': "Service 'vault' check",
                'Node': 'node2',
                'Notes': '',
                'Output': '',
                'ServiceID': 'vault',
                'ServiceName': 'vault',
                'Status': 'passing'
            }
        ],
        'Node': {
            'Address': '172.17.0.4',
            'CreateIndex': 9,
            'ModifyIndex': 21,
            'Node': 'node2'
        },
        'Service': {
            'Address': '',
            'CreateIndex': 21,
            'EnableTagOverride': False,
            'ID': 'vault',
            'ModifyIndex': 21,
            'Port': 8200,
            'Service': 'vault',
            'Tags': ['secrets']
        }
    },
    {
        'Checks': [
            {
                'CheckID': 'serfHealth',
                'CreateIndex': 11,
                'ModifyIndex': 11,
                'Name': 'Serf Health Status',
                'Node': 'node3',
                'Notes': '',
                'Output': 'Agent alive and reachable',
                'ServiceID': '',
                'ServiceName': '',
                'Status': 'passing'
            },
            {
                'CheckID': 'service:vault',
                'CreateIndex': 16,
                'ModifyIndex': 16,
                'Name': "Service 'vault' check",
                'Node': 'node3',
                'Notes': '',
                'Output': '',
                'ServiceID': 'vault',
                'ServiceName': 'vault',
                'Status': 'warning'
            }
        ],
        'Node': {
            'Address': '172.17.0.5',
            'CreateIndex': 11,
            'ModifyIndex': 16,
            'Node': 'node3'
        },
        'Service': {
            'Address': '',
            'CreateIndex': 16,
            'EnableTagOverride': False,
            'ID': 'vault',
            'ModifyIndex': 16,
            'Port': 8200,
            'Service': 'vault',
            'Tags': ['secrets']
        }
    },
    {
        'Checks': [
            {
                'CheckID': 'serfHealth',
                'CreateIndex': 13,
                'ModifyIndex': 13,
                'Name': 'Serf Health Status',
                'Node': 'node4',
                'Notes': '',
                'Output': 'Agent alive and reachable',
                'ServiceID': '',
                'ServiceName': '',
                'Status': 'passing'
            },
            {
                'CheckID': 'service:vault',
                'CreateIndex': 23,
                'ModifyIndex': 23,
                'Name': "Service 'vault' check",
                'Node': 'node4',
                'Notes': '',
                'Output': '',
                'ServiceID': 'vault',
                'ServiceName': 'vault',
                'Status': 'warning'
            }
        ],
        'Node': {
            'Address': '172.17.0.6',
            'CreateIndex': 13,
            'ModifyIndex': 23,
            'Node': 'node4'
        },
        'Service': {
            'Address': '',
            'CreateIndex': 23,
            'EnableTagOverride': False,
            'ID': 'vault',
            'ModifyIndex': 23,
            'Port': 8200,
            'Service': 'vault',
            'Tags': ['secrets']
        }
    }
]

# same as above, but no passing vault check
test_get_active_node_none = deepcopy(test_get_active_node)
test_get_active_node_none[2]['Checks'][1]['Status'] = 'warning'
