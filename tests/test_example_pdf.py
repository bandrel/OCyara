#!/usr/env python3
from ocyara.ocyara import OCyara

ocy = OCyara('Example.pdf')
ocy.run('example.yara')


def num_rules():
    return len(ocy.list_rules())

def test_number_of_rules():
    assert num_rules == 3