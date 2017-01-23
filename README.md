# OCyara
[![Build Status](https://travis-ci.org/bandrel/OCyara.svg?branch=master)](https://travis-ci.org/bandrel/OCyara)

The OCyara module performs OCR (Optical Character Recognition) on image
files and scans them for matches to Yara rules.  OCyara also can process
images embedded in PDF files. For more information about Yara, visit
https://virustotal.github.io/yara/.

## Installation
### Operating System Requirements

- **Python 3.5+**
- **Debian-based Linux distros** are currently the only supported
  operating systems. Testing has only been performed against Kali
  Rolling and Ubuntu 16.04. Other Debian-based distros may work as
  well.
- **Tesseract OCR API**
  To install Tesseract:

  1. `apt-get update`
  1. Install python3 header files: `apt-get install python3-dev`
  2. Install Tesseract and its required libraries:
     `apt-get install tesseract-ocr libtesseract-dev libleptonica-dev
     libpng12-dev libjpeg62-dev libtiff5-dev zlib1g-dev`



### Install Procedure
The easiest way to install OCyara is through the use of pip:

  1. Ensure all the Operating System Requirements listed above have been met
  3. Run `pip install cython` (has to be installed separate like this
     due to cython currently lacking an "install_requires")
  2. Run `pip install ocyara`

Along with OCyara, the following other packages will be automatically
installed:
 - **cython** (>=0.25.2) A compiler for writing C extensions for the
   Python language. Used by the tesserocr python module.
   https://pypi.python.org/pypi/Cython/
 - **tesserocr** (>=2.1.3) A Python wrapper for the tesseract-ocr API
   https://github.com/sirfz/tesserocr
 - **yara-python** (>=3.5.0) The Python interface for YARA
   https://github.com/VirusTotal/yara-python
 - **pillow** (>=4.0.0) Python Imaging Library fork
   https://github.com/python-pillow/Pillow


## Usage


### OCyara Class Usage Examples

```python
# Scan the current directory recursively for files that match rules in
# "rulefile.yara"

from ocyara import OCyara

test = OCyara('./', recursive=True)
test.run('rulefile.yara')
print(test.list_matches())
```

Returns:
```
Visa tests/Example.pdf
SSN tests/Example.pdf
American_Express tests/Example.pdf
Diners_Club tests/Example.pdf
JCB tests/Example.pdf
Discover tests/Example.pdf
credit_card tests/Example.pdf
MasterCard tests/Example.pdf
card tests/Example.pdf
```

Each line printed has the rule that was matched and the file that
matched it.

### CLI usage Example
OCyara is not primarily intended to be used from the command line, but
basic cli capablilities have been implemented to allow for
easily-approachble testing of the library's core functionality.

```
usage: ocyara.py [-h] YARA_RULES_FILE TARGET_FILE/S`

positional arguments:

  YARA_RULES_FILE  Path of file containing yara rules
  TARGET_FILE/S    Directory or file name of images to scan.

optional arguments:
  -h, --help       show this help message and exit
```

### OCyara Class Structure

```
class OCyara(builtins.object)
 |  Performs OCR (Optical Character Recognition) on image files and scans for matches to Yara rules.
 |
 |  OCyara also can process images embedded in PDF files.
 |
 |  Methods defined here:
 |
 |  __init__(self, path, recursive=False, worker_count=8)
 |      Create an OCyara object that can scan the specified directory or file and store the results.
 |
 |      Arguments:
 |          path -- File or directory to be processed
 |
 |      Keyword Arguments:
 |          recursive -- Whether the specified path should be recursivly searched for images (default False)
 |          worker_count -- The number of worker processes that should be spawned when
 |            run() is executed (default availble CPUcores * 2)
 |
 |  __repr__(self)
 |      Return a list of matches when the class object is directly referenced
 |
 |  join(self)
 |      Join the main thread to the scan queue and wait for workers to complete before proceding.
 |
 |  list_matches(self, rulename)
 |      Find scanned files that matched the specified rule and return them in a dictionary.
 |
 |  list_rules(self)
 |      Process the matchedfiles dictionary and return a list of rules that were matched.
 |
 |  pdf_extract(self, pdffile)
 |      Extract jpg images from pdf files and save them to temp directory.
 |
 |      pdf_extract is used by the run() method and not be called directly in most
 |      circumstances.
 |
 |      Arguments:
 |          pdffile -- A string file path pointing to a PDF
 |
 |  process_image(self, yara_rule)
 |      Perform OCR and yara rule matching as a worker.
 |
 |      process_image() is used by the run() method to create multiple worker processes for
 |      parallel execution.  process_image normally will not be called directly.
 |
 |      Arguments:
 |          yara_rule -- File path pointing to a Yara rule file
 |
 |  run(self, yara_rule, auto_join=True)
 |      Begin multithreaded processing of path files with the specified rule file.
 |
 |      Arguments:
 |          yara_rule -- A string file path of a Yara rule file
 |
 |      Keyword Arguments:
 |          auto_join -- If set to True, the main process will stall until all the
 |            worker processes have completed their work. If set to False, join()
 |            must be manually called following run() to ensure the queue is
 |            cleared and all workers have terminated.
```
