from setuptools import find_namespace_packages, setup

install_requires = [
    "click>=7.1.2",
    "requests>=2.24.0",
    "jsonschema>=4.7.2",
]

tests_require = [
    "pytest",
]

dev_require = [
    *tests_require,
    "black",
    "click-man",
    "flake8",
    "isort",
    "mypy",
    "tox",
    "types-click",
    "types-requests",
    "types-jsonschema",
]

extras_require = {
    "dev": dev_require,
    "test": tests_require,
}

with open("README.md") as f:
    readme = f.read()

with open("cvelib/__init__.py") as f:
    for line in f:
        if line.startswith("__version__"):
            delim = '"' if '"' in line else "'"
            version = line.split(delim)[1]
            break
    else:
        raise RuntimeError("Unable to find version string.")

setup(
    name="cvelib",
    version=version,
    description="A library and command line interface for the CVE Project services.",
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/RedHatProductSecurity/cvelib",
    author="Red Hat Product Security",
    author_email="secalert@redhat.com",
    license="MIT",
    classifiers=[
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    include_package_data=True,
    packages=find_namespace_packages(),
    install_requires=install_requires,
    extras_require=extras_require,
    entry_points={
        "console_scripts": [
            "cve = cvelib.cli:cli",
        ],
    },
)
