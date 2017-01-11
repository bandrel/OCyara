#!/usr/bin/env python3

from ocyara import OCyara

test = OCyara(path='./')
test.run('example.yara', auto_join=False)
test.join()
print(test.list_matches('services'))
