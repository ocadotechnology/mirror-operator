import os
from setuptools import find_packages, setup
import versioneer
from setuptools.command.test import test as TestCommand

with open(os.path.join(os.path.dirname(__file__), 'README.md')) as readme:
    README = readme.read()
# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))
test_dependencies = [
    'coverage',
    'urllib3_mock',
    'nose',
]
dependencies = [
    'bitmath==1.3.3.1',
    'kubernetes==11.0.0',
    'statsd==3.2.1',
    ]


class NoseTestCommand(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # Run nose ensuring that argv simulates running nosetests directly
        import nose
        nose.run_exit(argv=['nosetests'])

cmdclass = versioneer.get_cmdclass()
cmdclass['test'] = NoseTestCommand
setup(
    name='mirroroperator',
    packages=find_packages(),
    include_package_data=True,
    description='A python program for managing docker registry mirrors within a kubernetes cluster',
    long_description=README,
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.8',
    ],
    entry_points={
    },
    test_suite='tests',
    tests_require=test_dependencies,
    install_requires=dependencies,
    version=versioneer.get_version(),
    cmdclass=cmdclass
)
