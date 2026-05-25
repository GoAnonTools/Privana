from setuptools import setup, find_packages

setup(
    name="privana",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "click>=8.1.7",
        "requests>=2.32.0",
    ],
    entry_points={
        "console_scripts": [
            "privana=main:cli",
        ],
    },
    author="Privana Team",
    description="Your Private Road on the Internet",
    url="https://privana.pro",
)