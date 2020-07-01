from setuptools import setup, find_packages

setup(
    name="chiff",
    version="0.1",
    packages=find_packages(),
    url="https://github.com/chiff-app/chiff-cli",
    license="",
    author="Keyn B.V.",
    description="A command-line utility to create, update and delete Keyn seeds and accounts.",
    install_requires=[
        "tldextract==2.2.2",
        "pykeepass==3.2.0",
        "pynacl==1.4.0",
        "click==7.1.2",
        "pillow==7.1.2",
        "requests==2.22.0",
        "qrcode==6.1",
        "tabulate==0.8.7",
        "importlib-resources==2.0.1",
    ],
    include_package_data=True,
    python_requires=">=3",
    entry_points={"console_scripts": ["chiff=chiff.main:main"]},
)
