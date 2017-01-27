#!/usr/env python3
from ocyara import OCyara


def test_png():
    assert OCyara.check_file_type('tests/SSN-example.png') == 'image/png'


def test_jpg():
    assert OCyara.check_file_type('tests/SSN-example.jpg') == 'image/jpeg'


def test_pdf():
    assert OCyara.check_file_type('tests/Example.pdf') == 'application/pdf'

# todo verify tiff support works
# def test_tiff():
#     assert OCyara.check_file_type('tests/SSN-example.tif') == 'image/tiff'


def test_gif():
    assert OCyara.check_file_type('tests/SSN-example.gif') == 'image/gif'


def test_bmp():
    assert OCyara.check_file_type('tests/SSN-example.bmp') == 'image/x-ms-bmp'


def test_png_as_txt():
    assert OCyara.check_file_type('tests/SSN-example-png-as.txt') == 'image/png'


def test_png_as_jpg():
    assert OCyara.check_file_type('tests/SSN-example-png-as.jpg') == 'image/png'
