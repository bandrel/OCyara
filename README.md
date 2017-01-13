# OCyara

The OCyara module performs OCR (Optical Character Recognition) on image
files and scans them for matches to Yara rules.  OCyara also can process
images embedded in PDF files. For more informationabout Yara, visit
https://virustotal.github.io/yara/.

## Requirements

### Operating System
Only

### Python Packages
 - tesserocr>=2.1.3
 - yara-python>=3.5.0

## OCyara Class Usage

## CLI usage

OCyara is not primarily intended to be used from the cli, but basic cli
capablilities has been implemented to allow for easily-approachble
testing of the library's core functionality

```
usage: ocyara.py [-h] YARA_RULES_FILE TARGET_FILE/S`

positional arguments:

  YARA_RULES_FILE  Path of file containing yara rules
  TARGET_FILE/S    Directory or file name of images to scan.

optional arguments:
  -h, --help       show this help message and exit
```
