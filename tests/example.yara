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
rule Visa
{
    strings:
        $visa = /\b4[0-9]{12}([0-9]{3})?\b/
    condition:
       $visa
}
rule MasterCard
{
    strings:
        $mc = /\b(5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b/
    condition:
       $mc
}
rule American_Express
{
    strings:
        $amex = /\b3[47][0-9]{13}\b/
    condition:
       $amex
}
rule Diners_Club
{
    strings:
        $diners = /\b3(0[0-5]|[68][0-9])[0-9]{11}\b/
    condition:
       $diners
}
rule Discover
{
    strings:
        $discover = /\b6(011|5[0-9]{2})[0-9]{12}\b/
    condition:
       $discover
}
rule JCB
{
    strings:
        $jcb = /\b(2131|1800|35\d{3})\d{11}\b/
    condition:
       $jcb
}