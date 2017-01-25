#!/usr/env python3
from ocyara import OCyara


def test_valid_log_levels():
    keywords = [0, 1, 2, 3, -1]
    for verbose_level in keywords:
        try:
            ocy = OCyara('tests/Example.pdf', verbose=verbose_level)
        except TypeError:
            assert False


def test_invalid_log_levels():
    keywords = ['Foo', '', None]
    for verbose_level in keywords:
        try:
            ocy = OCyara('tests/Example.pdf', verbose=verbose_level)
            assert False
        except TypeError:
            continue
    assert True
