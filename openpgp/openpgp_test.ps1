Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'
. .\openpgp.ps1
. .\rsa.ps1

$keyDBFP = @{}
$keyDBID = @{}

function Get-KeyByFP($fp) {
    if($keyDBFP.ContainsKey($fp)) {
        return $keyDBFP.$fp
    }
    return $null
}

function Get-KeyByID($id) {
    if($keyDBID.ContainsKey($id)) {
        return $keyDBID.$id
    }
    return $null
}

function Get-Key($file) {
    $pk = Get-OpenPGPPacket $file
    $result = $null
    foreach($p in $pk.Packet) {
        switch ($p.TagType) {
            13 {
                $result.UserIDs += $p.Name
            }
            {@(5, 6, 7, 14) -contains $_} {
                $isPrimary = @(5, 6) -contains $_
                $isSecret = @(5, 7) -contains $_
                $dict = [System.Collections.Generic.Dictionary[string, byte[]]]::new()
                $p | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name | ForEach-Object {
                    if($p.$_.GetType() -eq [byte[]]) {
                        $dict.$_ = $p.$_
                    }
                }
                $keyInfo = [KeyInfo]::new($p.FingerPrint, $p.Algorithm.Key, $p.Algorithm.Value, $p.CreationTime, $isSecret, $dict)

                if($isPrimary) {
                    $result = [PSCustomObject]@{
                        'UserIDs' = @()
                        'PrimaryKey' = $keyInfo
                        'SubKeys' = @()
                    }
                } else {
                    $result.SubKeys += $keyInfo
                }

                $v = [PSCustomObject]@{
                    'MainKey' = $result
                    'Key' = $keyInfo
                }
                $keyDBID.($p.KeyID) = $v
                $keyDBFP.($p.FingerPrint) = $v
            }
            Default {}
        }
    }
}

function Test-KeySignature($file) {
    $pk = Get-OpenPGPPacket $file
    $mainKey = $pk.Packet | Where-Object {$_.TagType -eq 5 -or $_.TagType -eq 6}
    $user = $null
    $subKey = $null
    $sign = $null
    foreach($p in $pk.Packet) {
        if($p -eq $mainKey) {
            "MainKey" | Write-Verbose
            continue
        }
        if($p.TagType -eq 13) {
            $user = $p
            "UserTag" | Write-Verbose
            continue
        }
        if($p.TagType -eq 7 -or $p.TagType -eq 14) {
            $subKey = $p
            "SubKey" | Write-Verbose
            continue
        }
        if($p.TagType -ne 2) {
            throw "unexcepted type! $($p.TagTypeName)"
        }
        $sign = $p
        $type = $sign.SignatureType.Key
        $typeName = $sign.SignatureType.Value

        [byte[]]$keyHashData = @()
        switch ($type) {
            {@(0x10, 0x13) -contains $_} {
                "Verify ${type}: $typeName $($mainKey.KeyID) for $($user.Name)" | Write-Verbose
                $keyHashData = [byte]0x99
                $len = $mainKey.HashData.Length
                for($j = 1; $j -ge 0; $j--) {
                    $keyHashData += [byte](($len -shr (8 * $j)) -band 0xff)
                }
                $keyHashData += $mainKey.HashData

                $keyHashData += [byte]0xB4
                $len = $user.HashData.Length
                for($j = 3; $j -ge 0; $j--) {
                    $keyHashData += [byte](($len -shr (8 * $j)) -band 0xff)
                }
                $keyHashData += $user.HashData
            }
            0x18 {
                "Verify ${type}: $typeName $($subKey.KeyID) for $($mainKey.KeyID)" | Write-Verbose
                $keyHashData += [byte]0x99
                $len = $mainKey.HashData.Length
                for($j = 1; $j -ge 0; $j--) {
                    $keyHashData += [byte](($len -shr (8 * $j)) -band 0xff)
                }
                $keyHashData += $mainKey.HashData

                $len = $subKey.HashData.Length
                $keyHashData += [byte]0x99
                for($j = 1; $j -ge 0; $j--) {
                    $keyHashData += [byte](($len -shr (8 * $j)) -band 0xff)
                }
                $keyHashData += $subKey.HashData
            }
            Default {
                throw ("Unexcepted SignatureType! 0x{0:X2}: $typeName" -f $type)
            }
        }
        $hash = Get-SignatureHash $keyHashData $sign
        if(!$hash.StartsWith($sign.Hash16)) {
            $sign.Hash16
            $hash
            throw 'invalid hash!'
        }
        $issuer = $sign.HashedSubpacket | Where-Object {$_.Type -eq 33}
        $verifyKey = Get-KeyByFP $issuer.FingerPrint
        if($null -eq $verifyKey) {
            "key: $($issuer.FingerPrint) not found. skip signature" | Write-Verbose
            continue
        }
        $dec = $verifyKey.Key.Key.Verify($sign.Signature)
        if($null -eq $dec) {
            "verify not implemented" | Write-Verbose
            return
        }
        $asn1 = ConvertFrom-ASN1 $dec
        $hash2 = ConvertTo-Hex $asn1.Hash $true
        if($hash -eq $hash2) {
            $hash
            "Signature verified"
        } else {
            $hash
            $hash2
        }
    }
}

function Test-OnePassSignature($file) {
    "Verify $file" | Write-Verbose
    $sign = Get-OpenPGPPacket $file
    $literal = $sign.Packet | Where-Object {$_.TagType -eq 11}
    $signature = $sign.Packet | Where-Object {$_.TagType -eq 2}
    $hash = Get-SignatureHash $literal.BinaryData $signature
    if(!$hash.StartsWith($signature.Hash16)) {
        $signature.Hash16
        $hash
        throw 'Invalid Hash'
    }

    $key = $null
    $keyID = $signature.HashedSubpacket | Where-Object {$_.Type -eq 33}
    if($null -ne $keyID) {
        $id = $keyID.FingerPrint
        $key = Get-KeyByFP $keyID.FingerPrint
    }
    if($null -eq $key) {
        $keyID = $signature.Subpacket | Where-Object {$_.Type -eq 16}
        if($null -ne $keyID) {
            $key = Get-KeyByID $keyID.IssuerID
            $id = $keyID.IssuerID
        }
    }
    if($null -eq $key) {
        throw "No public key Found $id"
    }

    $dec = $key.Key.Key.Verify($signature.Signature)
    if($null -eq $dec) {
        "verify not implemented" | Write-Verbose
        return
    }
    $asn1 = ConvertFrom-ASN1 $dec
    $hash2 = ConvertTo-Hex $asn1.Hash $true
    if($hash -eq $hash2) {
        $hash
        "Signature verified"
    } else {
        $hash
        $hash2
    }
}

function Test-DetachedSignature($file, $key) {
    $f = Get-Item $file
    $main = $file -replace "$($f.Extension)$"
    "Verify $file for $main" | Write-Verbose
    $detsign = Get-OpenPGPPacket $file
    if(!(Test-Path $main)) {
        throw 'data not found'
    }
    $sign = $detsign.Packet[0]
    $key = $null
    $keyID = $sign.HashedSubpacket | Where-Object {$_.Type -eq 33}
    if($null -ne $keyID) {
        $id = $keyID.FingerPrint
        $key = Get-KeyByFP $keyID.FingerPrint
    }
    if($null -eq $key) {
        $keyID = $sign.Subpacket | Where-Object {$_.Type -eq 16}
        if($null -ne $keyID) {
            $key = Get-KeyByID $keyID.IssuerID
            $id = $keyID.IssuerID
        }
    }
    if($null -eq $key) {
        throw "No public key Found $id"
    }
    $fm = Get-Item $main
    #$data = Get-Content -AsByteStream $main
    #$hash = Get-SignatureHash $data $sign
    $fs = [System.IO.FileStream]::new($fm.FullName, [System.IO.FileMode]::Open)
    $hash = Get-SignatureHashFromStream $fs $sign
    $fs.Close()
    if(!$hash.StartsWith($sign.Hash16)) {
        $sign.Hash16
        $hash
        throw 'Invalid Hash'
    }
    $dec = $key.Key.Key.Verify($detsign.Packet[0].Signature)
    if($null -eq $dec) {
        "verify not implemented" | Write-Verbose
        return
    }
    $hash2 = ConvertFrom-ASN1 $dec
    $hash2 = ConvertTo-Hex $hash2.Hash $true
    if($hash -eq $hash2) {
        $hash2
        "Signature verified"
    } else {
        $hash.Hash
        $hash2
    }
}

function Get-SignAndDecrypt($file) {
    $p = Get-OpenPGPPacket $file
    $sesKey = $p.Packet | Where-Object {$_.TagType -eq 1} | ForEach-Object {
        $key = Get-KeyByID $_.KeyID
        if($null -eq $key) {return}
        return $_
    }
    $sesKey | ForEach-Object {
        $key = Get-KeyByID $_.KeyID
        Get-SessionInfo $_ $key.Key.Key
    }
    $p.Packet | Where-Object {$_.TagType -eq 3} | Format-List

    $p.Packet | Where-Object {$_.TagType -eq 18} | Format-List
}

$null = Get-Key ".\test\test_0x5A35FE17_public.asc"
Test-KeySignature ".\test\test_0x5A35FE17_public.asc"
Test-KeySignature ".\test\test_0x5A35FE17_SECRET.asc"
Test-OnePassSignature ".\test\test_0x5A35FE17_SECRET.asc.gpg" # binary
Test-DetachedSignature ".\test\test_0x5A35FE17_SECRET.asc.asc" # armored signature
Test-DetachedSignature ".\test\test_0x5A35FE17_SECRET.asc.sig" # binary signature
