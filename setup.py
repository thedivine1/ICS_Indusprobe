from setuptools import setup, find_packages

setup(
    name="indus-probe",
    version="1.0.0",
    description="OT Passive Scanner & IEC 62443 Gap Assessment Tool",
    author="Industrial Cybersecurity Suite",
    packages=find_packages(),
    install_requires=[
        "pyshark>=0.6.0",
        "scapy>=2.5.0",
        "rich>=13.0.0",
        "jinja2>=3.1.0",
        "tabulate>=0.9.0",
    ],
    entry_points={
        "console_scripts": [
            "indus-probe=indus_probe.cli:main",
            "indus-advisory=indus_probe.advisory.cli:main",
        ],
    },
    python_requires=">=3.9",
)

