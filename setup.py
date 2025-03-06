from setuptools import setup, find_packages

setup(
    name="threat_model",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "pydantic>=2.0.0",
        "ruamel.yaml>=0.17.0",
        "jsonschema>=4.17.0"
    ],
    python_requires=">=3.13",
    author="Cline",
    description="A tool for generating threat models with batch summaries",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3.13",
    ],
)
