#!/usr/env python3
from ocyara import OCyara


def num_unique_rule_matches():
    return len(ocy.list_matched_rules())


def test_number_of_rules():
    assert num_unique_rule_matches() == 9


def test_example_pdf_rules():
    assert ocy.list_matched_rules() == {'card',
                                'SSN',
                                'credit_card',
                                'JCB',
                                'Diners_Club',
                                'Visa',
                                'American_Express',
                                'MasterCard',
                                'Discover'
                                        }


def test_dict_matches():
    findings = list(map(ocy.matchedfiles[0].get, [
        'tests/SSN-example.png', 'tests/SSN-example-png-as.jpg', 'tests/Example.pdf'
    ]))

    assert findings == [
        [('SSN', None)],
        [('SSN', None)],
        [('SSN', None), ('credit_card', None), ('card', None), ('Visa', None), ('MasterCard', None),
         ('American_Express', None), ('Diners_Club', None), ('Discover', None), ('JCB', None)]
    ]

ocy = OCyara('tests/')
ocy.run('tests/example.yara')
