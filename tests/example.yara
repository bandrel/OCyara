rule SSN
{
    strings:
       $a = /\d{3}-?\d{2}-?\d{4}/
    condition:
       $a
}

rule credit_card
{
    strings:
        $a = /\d{16}/
    condition:
       $a
}

rule card
{
    strings:
        $a = /[Cc]ard/
    condition:
       $a
}
