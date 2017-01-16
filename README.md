# OCyara

The OCyara module performs OCR (Optical Character Recognition) on image
files and scans them for matches to Yara rules.  OCyara also can process
images embedded in PDF files. For more information about Yara, visit
https://virustotal.github.io/yara/.

## Installation
### Operating System Requirements

- **Python 3.x**
- **Debian-based Linux distros** are currently the only supported
  operating systems. Testing has only been performed against Kali
  Rolling, but Ubuntu and other Debian-based distros should work as
  well.
- **Tesseract OCR API**
  To install Tesseract:

  1. Install python3 header files: `apt-get install python3-dev`
  2. `apt-get install tesseract-ocr libtesseract-dev libleptonica-dev`



### Install Procedure
The easiest way to install OCyara is through the use of pip:

  1. Ensure all the Operating System Requirements listed above have been met
  2. Run `pip install ocyara`

Along with OCyara, the following other packages will be automatically
installed:
 - **cython** (>=0.25.2) A compiler for writing C extensions for the
   Python language. Used by the tesserocr python module.
   https://pypi.python.org/pypi/Cython/

 - **tesserocr** (>=2.1.3) A Python wrapper for the tesseract-ocr API
   Run `pip install tesserocr` to install manually.
   https://github.com/sirfz/tesserocr
 - **yara-python** (>=3.5.0) The Python interface for YARA
   https://github.com/VirusTotal/yara-python
 - **pillow** (>=4.0.0) Python Imaging Library fork
   https://github.com/python-pillow/Pillow


## Usage
OCyara is not primarily intended to be used from the command line, but
basic cli capablilities have been implemented to allow for
easily-approachble testing of the library's core functionality.

### OCyara Class Usage

### CLI usage


```
usage: ocyara.py [-h] YARA_RULES_FILE TARGET_FILE/S`

positional arguments:

  YARA_RULES_FILE  Path of file containing yara rules
  TARGET_FILE/S    Directory or file name of images to scan.

optional arguments:
  -h, --help       show this help message and exit
```
