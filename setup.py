from setuptools import setup, find_packages

setup(
    name='OCyara',
    version='0.0.1',
    packages=find_packages(),
    url='https://github.com/bandrel/OCyara',
    license='GPL v3',
    author='Bandrel & ryman1',
    author_email='example@example.com',
    description='A Yara rule engine that scans images for matches using Optical Character Recognition (OCR)',
    install_requires=['pillow>=4.0.0', 'tqdm', 'cython>=0.25.2', 'tesserocr>=2.1.3', 'yara-python>=3.5.0']
)
