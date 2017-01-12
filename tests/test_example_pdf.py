#!/usr/env python3
from OCyara.ocyara import OCyara

ocy = OCyara('Example.pdf')
ocy.run('example.yara')


def num_unique_rule_matches():
    return len(ocy.list_rules())


def test_number_of_rules():
    assert num_unique_rule_matches() == 3

def test_example_pdf_rules():
    assert ocy.list_rules() == {'card', 'SSN', 'credit_card'}
