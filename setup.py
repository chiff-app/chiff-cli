from setuptools import setup, find_packages

setup(
    name='keyn',
    version='1.0',
    packages=find_packages(),
    url='https://github.com/keyn-app/keyn-cli',
    license='',
    author='Keyn B.V.',
    description='A command-line utility to create, update and delete Keyn seeds and accounts.',
    install_requires=[
        'tldextract==2.2.1',
        'pykeepass==3.0.3',
        'pynacl @ git+https://github.com/bas-d/pynacl.git',
        'click==7.0',
        'requests==2.22.0'
    ],
    python_requires='>=3',
    entry_points={
        'console_scripts': [
            'keyn=keyn.main:main',
        ],
    },
)
