import os

from setuptools import setup, find_packages


def read(fname):
    readme_file_path = os.path.join(os.path.dirname(__file__), fname)

    if os.path.exists(readme_file_path) and os.path.isfile(readme_file_path):
        readme_file = open(readme_file_path)
        return readme_file.read()
    else:
        return "The SoftFIRE Security Manager"


setup(
    name="security-manager",
    version="0.1.1",
    author="SoftFIRE",
    author_email="softfire@softfire.eu",
    description="The SoftFIRE Security Manager",
    license="Apache 2",
    keywords="python vnfm nfvo open baton openbaton sdk experiment manager softfire tosca openstack rest security firewall ips",
    url="https://github.com/softfire-eu/security-manager",
    packages=find_packages(),
    scripts=["security-manager"],
    install_requires=[
        'IPy',
        'openbaton-cli',
        'PyYAML',
        'requests',
        'softfire-sdk'
        ],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",

    ],
)
