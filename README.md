# OCyara
[![Build Status](https://travis-ci.org/bandrel/OCyara.svg?branch=master)](https://travis-ci.org/bandrel/OCyara)

[![PyPI version](https://badge.fury.io/py/OCyara.svg)](https://pypi.python.org/pypi/OCyara/)

The OCyara module performs OCR (Optical Character Recognition) on image
files and scans them for matches to Yara rules.  OCyara also can process
images embedded in PDF files. For more information about Yara, visit
https://virustotal.github.io/yara/.

## Installation
### Operating System Requirements

- **Python 3.5+**
- **Debian-based Linux distros** are currently the only supported
  operating systems. Installation has only been tested on Kali
  Rolling and Ubuntu 16.10. (Other Debian-based distros may work as
  well, but may require manual compilation of Tesseract and/or Leptonica
  to get support for all image types. GIF, and TIFF library support
  seems to be troublesome with some Ubuntu LTS installations.)
- **Tesseract OCR API**
  To install Tesseract:

  1. `apt-get update`
  1. Install python3 header files: `apt-get install python3-dev`
  2. Install Tesseract and its required libraries:
     `apt-get install tesseract-ocr libtesseract-dev libleptonica-dev
      libpng12-dev libjpeg62-dev libtiff5-dev zlib1g-dev`



### Install Procedure
The easiest way to install OCyara is through the use of pip:

  1. Ensure all the Operating System Requirements listed above have been
     met
  3. Run `pip install cython` (has to be installed separate like this
     due to tesserocr currently lacking an "install_requires")
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
 - **tqdm** A fast, extensible progress bar for Python and CLI
   https://github.com/tqdm/tqdm
 - **colorlog**
   A colored formatter for the python logging module
   http://pypi.python.org/pypi/colorlog


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
 |  __call__(self)
 |      Default call which outputs the results with the same output standard as the regular yara program
 |
 |  __init__(self, path:str, recursive=False, worker_count=6, verbose=0) -> None
 |      Create an OCyara object that can scan the specified directory or file and store the results.
 |
 |      Arguments:
 |          path -- File or directory to be processed
 |
 |      Keyword Arguments:
 |          recursive -- Whether the specified path should be recursivly searched for images (default False)
 |          worker_count -- The number of worker processes that should be spawned when
 |                          run() is executed (default available CPU cores * 2)
 |          verbose -- An int() from 0-2 that sets the verbosity level.
 |                     0 is default, 1 is information and 2 is debug
 |
 |  join(self, showprogress=True)
 |
 |  list_matched_rules(self) -> set
 |      Process the matchedfiles dictionary and return a list of rules that were matched.
 |
 |  list_matches(self, rules=None) -> typing.Dict
 |      List matched files and thier contexts (if available) in dictionary form.
 |
 |      Keyword Arguments:
 |
 |          rules -- Accepts a string or list of strings indicating specific rules.
 |            Only matches pertaining to the specified rule/s will be returned. If no
 |            rules are specified, all matches will be returned.
 |
 |  run(self, yara_rule:str, auto_join=True, file_magic=False, save_context=False) -> None
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
 |
 |          file_magic -- If file_magic is enabled, ocyara will examine the contents
 |            of the target files to determine if they are an eligible image file
 |            type. For example, a JPEG file named 'picture.txt' will be processed by
 |            the OCR engine. file_magic uses the Linux "file" command.
 |
 |          include_context -- If True, when a file matches a yara rule, the returned
 |            results dictionary will also include the full ocr text of the matched
 |            file. This text can be further processed by the user if needed.
 |
 |  show_progress(self) -> None
 |      Generate a progress bar based on the number of items remaining in queue.
 |
 |  ----------------------------------------------------------------------
 |  Static methods defined here:
 |
 |  check_file_type(path:str) -> str
 |      Use the Linux "file" command to determine a file's type based on contents
 |      instead of file extension.
 |
 |      Arguments:
 |          path -- A string file path to be processed
 |
 |  ----------------------------------------------------------------------
 |  Data descriptors defined here:
 |
 |  __dict__
 |      dictionary for instance variables (if defined)
 |
 |  __weakref__
 |      list of weak references to the object (if defined)
 |
 |  yara_output
 |      Returns the same output format as the standard yara program:
 |      RuleName FileName, FileName
 |      RuleName FileName...
 |
 |      Where:
 |        RuleName is the name of the rule that was matched
 |        FileName is the name of the file in which the match was found
```
