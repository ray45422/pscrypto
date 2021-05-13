$ASN1_OBJECT_IDENTIFIERS = @{
    '1.2.840.113549.2.5' = [PSCustomObject]@{
        'ObjectID' = '1.2.840.113549.2.5'
        'Name' = 'MD5'
    }
    '1.3.36.3.2.1' = [PSCustomObject]@{
        'ObjectID' = '1.3.36.3.2.1'
        'Name' = 'RIPEMD-160'
    }
    '1.3.14.3.2.26' = [PSCustomObject]@{
        'ObjectID' = '1.3.14.3.2.26'
        'Name' = 'SHA-1'
    }
    '2.16.840.1.101.3.4.2.4' = [PSCustomObject]@{
        'ObjectID' = '2.16.840.1.101.3.4.2.4'
        'Name' = 'SHA2-224'
    }
    '2.16.840.1.101.3.4.2.1' = [PSCustomObject]@{
        'ObjectID' = '2.16.840.1.101.3.4.2.1'
        'Name' = 'SHA2-256'
    }
    '2.16.840.1.101.3.4.2.2' = [PSCustomObject]@{
        'ObjectID' = '2.16.840.1.101.3.4.2.2'
        'Name' = 'SHA2-384'
    }
    '2.16.840.1.101.3.4.2.3' = [PSCustomObject]@{
        'ObjectID' = '2.16.840.1.101.3.4.2.3'
        'Name' = 'SHA2-512'
    }
    '1.2.840.10045.3.1.7' = [PSCustomObject]@{
        'ObjectID' = '1.2.840.10045.3.1.7'
        'Name' = 'NIST P-256'
    }
    '1.3.132.0.34' = [PSCustomObject]@{
        'ObjectID' = '1.3.132.0.34'
        'Name' = 'NIST P-384'
    }
    '1.3.132.0.35' = [PSCustomObject]@{
        'ObjectID' = '1.3.132.0.35'
        'Name' = 'NIST P-521'
    }
    '1.3.36.3.3.2.8.1.1.7' = [PSCustomObject]@{
        'ObjectID' = '1.3.36.3.3.2.8.1.1.7'
        'Name' = 'brainpoolP256r1'
    }
    '1.3.36.3.3.2.8.1.1.13' = [PSCustomObject]@{
        'ObjectID' = '1.3.36.3.3.2.8.1.1.13'
        'Name' = 'brainpoolP512r1'
    }
    '1.3.6.1.4.1.11591.15.1' = [PSCustomObject]@{
        'ObjectID' = '1.3.6.1.4.1.11591.15.1'
        'Name' = 'Ed25519'
    }
    '1.3.6.1.4.1.3029.1.5.1' = [PSCustomObject]@{
        'ObjectID' = '1.3.6.1.4.1.3029.1.5.1'
        'Name' = 'Curve25519'
    }
}

function ConvertTo-Oid([byte[]]$Value) {
    $pos = 0

    $oid = ''
    $oid += [int]($Value[$pos] / 40)
    $oid += '.'
    $oid += $Value[$pos++] % 40

    while($pos -lt $Value.Length) {
        $v = 0
        while($true) {
            $t = $Value[$pos++]
            $v = $v -shl 7
            if($t -ge 0x80) {
                $v += $t -band 0b01111111
            } else {
                $v += $t
                break
            }
        }
        $oid += '.'
        $oid += $v
    }
    $oid
}
function ConvertFrom-Oid([string]$Oid) {
    $pos = 0
    $result = @()
    [long[]]$data = $Oid.Split('.')
    $result += [byte]($data[$pos++] * 40 + $data[$pos++])
    while($pos -lt $data.Length) {
        $d = $data[$pos++]
        $t = @()
        while($d -ge 0x80) {
            $t += [byte]($d -band 0b01111111)
            $d = $d -shr 7
        }
        $t += [byte]$d
        [array]::Reverse($t)
        for($i = 0; $i -lt $t.Length; $i++) {
            $p = 0x80
            if($i + 1 -eq $t.Length) {
                $p = 0
            }
            $result += [byte]($t[$i] + $p)
        }
    }
    return $result
}
