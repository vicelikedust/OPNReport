from setuptools import setup
import os.path

def read_file(filename):
    """Read a file into a string"""
    path = os.path.abspath(os.path.dirname(__file__))
    filepath = os.path.join(path, filename)
    try:
        with open(filepath, 'r') as fh:
            return fh.read()
    except IOError:
        return ''

setup(
    name='OPNReport',
    version='0.1',
    description='Generate meaningful output from your OPNSense configuration backup',
    long_description=read_file('README.md'),
    long_description_content_type='text/markdown',
    author='thyssenkrupp CERT',
    author_email='tkag-cert@thyssenkrupp.com',
    license='GPL-V3',
    url='https://github.com/andyx90/OPNReport',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: System :: Systems Administration',
        'Topic :: Text Editors :: Documentation',
        'Topic :: Text Processing'],
    py_modules=[
        'opnreport.util',
        'opnreport.opnsense',
        'opnreport.progress',
        'opnreport.parse',
        'opnreport.format',
        'opnreport.bbcode',
        'opnreport.markdown',
    ],
    entry_points = {
        'console_scripts': [
            'opn-parse=opnreport.parse:main',
            'opn-format=opnreport.format:main',
            'opnreport-parse=opnreport.parse:main',
            'opnreport-format=opnreport.format:main',
        ]
    },
    install_requires=read_file('requirements.txt').splitlines(),
    include_package_data=True,
)
