import os
from setuptools import setup, find_packages
from os.path import abspath, dirname, join

# Fetches the content from README.md
# This will be used for the "long_description" field.
README_MD = open(join(dirname(abspath(__file__)), "README.md")).read()

# here - where we are.
here = os.path.abspath(os.path.dirname(__file__))

# Path to the about.py file
init_py_path = join(here, "friTap", "about.py")

# Read version and author from about.py
with open(init_py_path) as f:
    exec(f.read())

# read the package requirements for install_requires
#with open(os.path.join(here, 'requirements.txt'), 'r') as f:
#    requirements = f.readlines()

def get_version():
    about = {}
    with open(init_py_path) as f:
        exec(f.read(), about)
    return about["__version__"]


# Define dependencies directly in setup.py
requirements = [
    'frida>=15.0.0',
    'frida-tools>=10.0.0',
    'AndroidFridaManager',
    'hexdump',
    'scapy',
    'watchdog',
    'click',
    'importlib-resources',
    'psutil'
]


setup(
    # pip install friTap
    name="friTap",
    version=get_version(),  # Dynamically get the version from about.py

    # The description that will be shown on PyPI.
    description="Simplifying SSL/TLS traffic analysis for researchers by making SSL/TLS decryption effortless. Decrypts and logs a process's SSL/TLS traffic on all major platforms. Further it allows the SSL/TLS key extraction.",

    # The content that will be shown on your project page.
    # In this case, we're displaying whatever is there in our README.md file
    long_description=README_MD,

    # Now, we'll tell PyPI what language our README file is in.
    long_description_content_type="text/markdown",


    url="https://github.com/fkie-cad/friTap",

    author_name=__author__,
    author_email="daniel.baier@fkie.fraunhofer.de",
    license='GPL v3',

     # include other files
    package_data={
        '': [os.path.join(here, 'friTap/_ssl_log.js'), os.path.join(here, 'friTap/_ssl_log_legacy.js'), # frida agent + frida legacy agent
        os.path.join(here, 'fritap/assets/tcpdump_binaries/tcpdump_arm64_android'), # tcpdump binarys 
        os.path.join(here, 'fritap/assets/tcpdump_binaries/tcpdump_arm32_android'),
        os.path.join(here, 'fritap/assets/tcpdump_binaries/tcpdump_x86_64_android'),
        os.path.join(here, 'fritap/assets/tcpdump_binaries/tcpdump_x86_android'), ],  
    },

    exclude_package_data={'': [os.path.join(here, 'create_standalone_release')]},


    include_package_data=True,
    python_requires='>=3.6',
    packages=find_packages(exclude=('create_legacy_agent','create_standalone_release')),
    install_requires=requirements,


    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Natural Language :: English",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: JavaScript",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers"
    ],

    # Keywords are tags that identify your project and help searching for it
    # This field is OPTIONAL
    keywords=["mobile", "instrumentation", "frida", "hook", "SSL decryption"],

    entry_points={
            'console_scripts': [
            'fritap=friTap.friTap:main',
        ],
    },

)

