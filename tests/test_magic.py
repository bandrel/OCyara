#!/usr/env python3
from ocyara import OCyara

png_with_magic = OCyara('tests/SSN-example.png')
png_with_magic.run('tests/example.yara', file_magic=True)

fake_jpg_with_magic = OCyara('tests/fake.jpg')
fake_jpg_with_magic.run('tests/example.yara', file_magic=True)

fake_jpg_without_magic = OCyara('tests/fake.jpg')
fake_jpg_without_magic.run('tests/example.yara', file_magic=True)

png_as_txt_with_magic = OCyara('tests/SSN-example.txt')
png_as_txt_with_magic.run('tests/example.yara', file_magic=True)

png_as_txt_without_magic = OCyara('tests/SSN-example.txt')
png_as_txt_without_magic.run('tests/example.yara', file_magic=False)

png_as_jpg_without_magic = OCyara('tests/SSN-example.jpg')
png_as_jpg_without_magic.run('tests/example.yara', file_magic=False)

png_as_jpg_with_magic= OCyara('tests/SSN-example.jpg')
png_as_jpg_with_magic.run('tests/example.yara', file_magic=True)

def test_png_as_txt_with_magic():
    assert png_with_magic.list_rules() == png_as_txt_with_magic.list_rules()

def test_png_as_txt_without_magic():
    assert png_with_magic.list_rules() != png_as_txt_without_magic.list_rules()

def test_png_as_txt_without_magic_rules():
    assert png_as_txt_with_magic.list_rules() != png_as_txt_without_magic.list_rules()

def test_list_png_with_magic_rules():
    assert png_as_txt_with_magic.list_rules() == {'SSN'}

def test_png_as_jpg_with_magic():
    assert png_as_jpg_with_magic.list_rules() == png_with_magic.list_rules()

def test_png_as_jpg_without_magic():
    assert png_as_jpg_without_magic.list_rules() == png_with_magic.list_rules()

def test_fake_jpg_withoutmagic():
    assert png_as_jpg_without_magic.list_rules() == {}

def test_fake_jpg_withmagic():
    assert png_as_jpg_without_magic.list_rules() == {}



