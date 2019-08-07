from setuptools import setup, find_packages

setup(
    name='keyn',
    version='0.1',
    packages=find_packages(),
    url='https://keyn.app',
    license='',
    author='keyn',
    author_email='',
    description='keyn-cli',
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        main=keyn:main
    '''
)
