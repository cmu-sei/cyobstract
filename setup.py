from setuptools import setup, find_packages

setup(
    name = "cyobstract",
    version = "0.0.dev",
    license = "Released under a BSD-style license, please see license.txt or contact permission@sei.cmu.edu for full terms.",
    packages = find_packages(exclude=["smoke", "smoke.*"]),
    install_requires=['future', 'progress']
)
