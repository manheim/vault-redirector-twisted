from setuptools import setup, find_packages
from sys import version_info
from vault_redirector.version import _VERSION, _PROJECT_URL

with open('README.rst') as file:
    long_description = file.read()

requires = [
    'requests',
    'twisted>=16.0.0'
]

extras_require = {
    'tls': ['pyOpenSSL', 'pem']
}

classifiers = [
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'Environment :: No Input/Output (Daemon)',
    'Environment :: Web Environment',
    'Framework :: Twisted',
    'Intended Audience :: Information Technology',
    'License :: OSI Approved :: MIT License',
    'Natural Language :: English',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Topic :: Internet',
    'Topic :: Internet :: WWW/HTTP',
    'Topic :: Security',
    'Topic :: System :: Networking',
    'Topic :: Utilities',
]

setup(
    name='vault-redirector',
    version=_VERSION,
    author='Manheim',
    author_email='tooling@manheim.com',
    packages=find_packages(),
    entry_points="""
    [console_scripts]
    vault-redirector = vault_redirector.runner:console_entry_point
    """,
    url=_PROJECT_URL,
    description='Python/Twisted application to redirect Hashicorp Vault client requests to the active node in a HA cluster',
    long_description=long_description,
    install_requires=requires,
    extras_require=extras_require,
    keywords="hashicorp vault vaultproject",
    classifiers=classifiers
)
