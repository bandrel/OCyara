#!/usr/env python3
from ocyara import OCyara


def num_unique_rule_matches():
    return len(ocy.list_matched_rules())


def test_number_of_rules():
    assert num_unique_rule_matches() == 9


def test_example_pdf_rules():
    assert ocy.list_matched_rules() == {
        'card',
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
        [
            ('SSN', None), ('credit_card', None), ('card', None), ('Visa', None), ('MasterCard', None),
            ('American_Express', None), ('Diners_Club', None), ('Discover', None), ('JCB', None)
        ]
    ]


def test_list_files_matching_rules():
    ssn_matches = ocy.list_matches('SSN')
    mastercard_matches = ocy.list_matches('MasterCard')
    assert (ssn_matches['SSN'],  mastercard_matches['MasterCard']) == (
        {
            ('tests/Example.pdf', None),
            ('tests/SSN-example.jpg', None),
            ('tests/SSN-example-png-as.jpg', None),
            ('tests/SSN-example.png', None),
            ('tests/SSN-example.bmp', None)
        },
        {
            ('tests/Example.pdf', None)
        }
    )


def test_list_files_matching_rules_with_context():
    ocy2 = OCyara('tests/')
    ocy2.run('tests/example.yara', save_context=True)
    jcb_matches = ocy2.list_matches('JCB')
    assert jcb_matches['JCB'] == (
        {
            ('tests/Example.pdf', 'Testing1234\n'
                                  '0001273456\n'
                                  '000123456\n'
                                  '\n'
                                  'Test credit card numbers\n'
                                  'American Express\n'
                                  '\n'
                                  'American Express\n'
                                  '\n'
                                  'American Express Corporate\n'
                                  'Australian BankCard\n'
                                  '\n'
                                  'Diners Ciub\n'
                                  '\n'
                                  'Diners Club\n'
                                  'Discover\n'
                                  'Discover\n'
                                  'JCB\n'
                                  '\n'
                                  'JCB\n'
                                  'MasterCard\n'
                                  'MasterCard\n'
                                  'Visa\n'
                                  '\n'
                                  'Visa\n'
                                  '\n'
                                  'Visa\n'
                                  '\n'
                                  '378282246310005\n'
                                  '\n'
                                  '371449635398431\n'
                                  '\n'
                                  '378734493671000\n'
                                  '\n'
                                  '5610591081018250\n'
                                  '\n'
                                  '30569309025904\n'
                                  '\n'
                                  '38520000023237\n'
                                  '\n'
                                  '6011111111111117\n'
                                  '\n'
                                  '6011000990139424\n'
                                  '\n'
                                  '3530111333300000\n'
                                  '\n'
                                  '3566002020360505\n'
                                  '\n'
                                  '5555555555554444\n'
                                  '\n'
                                  '5105105105105100\n'
                                  '\n'
                                  '4111111111111111\n'
                                  '\n'
                                  '4012888888881881\n'
                                  '\n'
                                  '4222222222222\n'
                                  '\n'
             )
        }
    )


def test_yara_output():
    assert sorted(ocy.yara_output.strip().split('\n')) == [
        'American_Express tests/Example.pdf',
        'Diners_Club tests/Example.pdf',
        'Discover tests/Example.pdf',
        'JCB tests/Example.pdf',
        'MasterCard tests/Example.pdf',
        'SSN tests/Example.pdf',
        'SSN tests/SSN-example-png-as.jpg',
        'SSN tests/SSN-example.bmp',
        'SSN tests/SSN-example.jpg',
        'SSN tests/SSN-example.png',
        'Visa tests/Example.pdf',
        'card tests/Example.pdf',
        'credit_card tests/Example.pdf'
    ]

ocy = OCyara('tests/')
ocy.run('tests/example.yara')


def test_ocyara_rerun():
    ocy_rerun_test = OCyara('tests/')
    ocy_rerun_test.run('tests/example.yara')
    ocy_rerun_test.run('tests/example.yara')
    assert ocy_rerun_test.list_matched_rules() == {
        'card',
        'SSN',
        'credit_card',
        'JCB',
        'Diners_Club',
        'Visa',
        'American_Express',
        'MasterCard',
        'Discover'
    }
