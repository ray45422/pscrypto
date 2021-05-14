Set-StrictMode -Version Latest

function Get-Values([byte[]]$data, $count = -1) {
    $idx = 0
    $val = @()
    while ($val.Length -ne $count) {
        $len = toUInt32 $data[$idx..($idx + 3)]
        $end = $idx + $len + 3
        if ($end -gt $data.Length) {
            throw "length too long: $end, $($data.Length)"
        }
        if ($len -eq 0) {
            $val += , @()
        } else {
            $val += , $data[($idx + 4)..($end)]
        }
        $idx = $end + 1
        if ($idx -gt $data.Length) {
            break
        }
    }
    return @{
        'Data'  = $val
        'Index' = $idx
    }
}

function checkPadding([byte[]]$data, $offset) {
    # 256バイト単位になるようにパディングされるので正しい値かをチェックする必要がある
    $c = 0
    for ($i = $offset; $i -lt $data.Length; $i++) {
        if ($data[$i] -ne ++$c) {
            throw 'invalid padding'
        }
    }
}

function decryptAES([byte[]]$data, [byte[]]$iv, $round) {
    throw 'not implemented'
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.IV = $iv
    $aes.Key = [System.Text.Encoding]::UTF8.GetBytes('12345')
    $decryptor = $aes.CreateDecryptor()
    $dec = $decryptor.TransformFinalBlock($data, 0, $data.Length);
    return $dec
}

function toUInt32([byte[]]$data) {
    [array]::Reverse($data)
    return [System.BitConverter]::ToUInt32($data, 0)
}

function Get-PrivateKeyImpl([byte[]]$data) {
    $b = $data

    # checkint1 何らかの乱数らしい
    $checkint1 = toUInt32 $b[0..3]

    # checkint2 何らかの乱数らしい
    $checkint2 = toUInt32 $b[4..7]

    $b = $b[8..($b.Length - 1)]

    $r = Get-Values $b 1
    $name = [System.Text.Encoding]::ASCII.GetString($r.Data[0]) # 鍵の種類
    $b = $b[($r.Index)..($b.Length - 1)]

    switch ($name) {
        'ssh-rsa' {
            $r = Get-Values $b 7
            $val = $r.Data
            checkPadding $b $r.Index

            [array]::Reverse($val[0])
            $modulus = [bigint]::new($val[0])

            [array]::Reverse($val[1])
            $public_exponent = [bigint]::new($val[1])

            [array]::Reverse($val[2])
            $privateKey = [bigint]::new($val[2])

            [array]::Reverse($val[3])
            $v1 = [bigint]::new($val[3])

            [array]::Reverse($val[4])
            $prime1 = [bigint]::new($val[4])

            [array]::Reverse($val[5])
            $prime2 = [bigint]::new($val[5])

            $comment = [System.Text.Encoding]::ASCII.GetString($val[6])

            return [PSCustomObject]@{
                'Name'          = $name
                'CheckInt1'     = $checkint1
                'CheckInt2'     = $checkint2
                'Modulus'       = $modulus
                'PrivateKey'    = $privateKey
                'PublicExpoent' = $public_exponent
                'V1'            = $v1
                'prime1'        = $prime1
                'prime2'        = $prime2
                'Comment'       = $comment
            }
        }
        'ecdsa-sha2-nistp256' {
            $r = Get-Values $b 4
            $val = $r.Data
            checkPadding $b $r.Index

            return [PSCustomObject]@{
                'Name'      = $name
                'Curvename' = [System.Text.Encoding]::UTF8.GetString($val[0])
                'EC_PointQ' = $val[1]
                'Value3'    = $val[2]
                'Comment'   = [System.Text.Encoding]::UTF8.GetString($val[3])
            }
        }
        'ssh-ed25519' {
            $r = Get-Values $b 3
            $val = $r.Data
            checkPadding $b $r.Index

            return [PSCustomObject]@{
                'Name'      = $name
                'PublicKey' = $val[0]
                'Value2'    = $val[1]
                'Comment'   = [System.Text.Encoding]::UTF8.GetString($val[2])
            }
        }
        'sk-ssh-ed25519@openssh.com' {
            $r = Get-Values $b 2
            $val = $r.Data

            <# 1バイトのフラグがある
                resident指定時には0x21、未指定時には0x01
                #>
            $flag = $b[$r.Index]

            $b = $b[($r.Index + 1)..($b.Length - 1)]
            $r = Get-Values $b 3
            $val += $r.Data
            checkPadding $b $r.Index

            return [PSCustomObject]@{
                'Name'        = $name
                'PublicKey'   = $val[0]
                'Application' = [System.Text.Encoding]::UTF8.GetString($val[1])
                'Flag'        = $flag
                'KeyHandle'   = $val[2]
                'Value1'      = $val[3]
                'Comment'     = [System.Text.Encoding]::UTF8.GetString($val[4])
            }
        }
        'sk-ecdsa-sha2-nistp256@openssh.com' {
            $r = Get-Values $b 3
            $val = $r.Data

            <# 1バイトのフラグがある
                resident指定時には0x21、未指定時には0x01
                #>
            $flag = $b[$r.Index]

            $b = $b[($r.Index + 1)..($b.Length - 1)]
            $r = Get-Values $b 3
            $val += $r.Data
            checkPadding $b $r.Index

            return [PSCustomObject]@{
                'Name'        = $name
                'CurveName'   = [System.Text.Encoding]::UTF8.GetString($val[0])
                'EC_PointQ'   = $val[1]
                'Application' = [System.Text.Encoding]::UTF8.GetString($val[2])
                'Flag'        = $flag
                'KeyHandle'   = $val[3]
                'Value1'      = $val[4]
                'Comment'     = [System.Text.Encoding]::UTF8.GetString($val[5])
            }
        }
        Default { throw "unsupported key type: $name" }
    }
}

function Get-PrivateKey($file) {
    $priv_key = Get-Content $file
    $import = $false
    $key = ''
    foreach ($l in $priv_key) {
        if ($l -ceq '-----BEGIN OPENSSH PRIVATE KEY-----') {
            $import = $true
            continue
        }
        if ($l -ceq '-----END OPENSSH PRIVATE KEY-----') {
            $import = $false
            break
        }
        if (!$import) {
            continue
        }
        $key += $l
    }

    $b = [System.Convert]::FromBase64String($key)

    $head = @()
    for ($i = 0; $i -lt $b.Length; $i++) {
        $d = $b[$i]
        if ($d -eq 0) {
            $i++
            break
        }
        $head += $d
    }
    $header = [System.Text.Encoding]::ASCII.GetString($head) # "openssh-key-v1"が固定で入っている

    $b = $b[$i..($b.Length - 1)]
    $r = Get-Values $b 3
    $val = $r.Data

    $cipher = [System.Text.Encoding]::UTF8.GetString($val[0]) # 暗号化のアルゴリズム 暗号化されていないときは"none"
    $kdfName = [System.Text.Encoding]::UTF8.GetString($val[1]) # 暗号化されているときは"bcrypt"が入るらしい されていないときは"none
    $b = $b[($r.Index)..($b.Length - 1)]

    $keyN = toUInt32 $b[0..3] # 鍵の数 1でハードコードされているらしいので真面目に読む必要はあまりない
    $b = $b[4..($b.Length - 1)]

    $r = Get-Values $b $keyN
    $pubKeys = $r.Data | ForEach-Object {
        Get-PublicKeyImpl $_
    }

    $b = $b[($r.Index)..($b.Length - 1)]

    $r = Get-Values $b $keyN
    $privKeys = $r.Data | ForEach-Object {
        $data = $_
        if($cipher -ne 'none') {
            # 暗号化がされている場合の処理 未実装
            $r = Get-Values $val[2] 1
            $salt = $r.Data[0]
            $round = toUInt32 $val[2][($r.Index)..($val[2].Length - 1)]
        
            #$data = decryptAES $data $salt $round
            return [PSCustomObject]@{
                'Encrypted' = $data
                'Salt' = $salt
                'Round' = $round
            }
        }
        Get-PrivateKeyImpl $data
    }
    for ($i = 0; $i -lt $pubKeys.Length; $i++) {
        [PSCustomObject]@{
            'AuthMagic'  = $header
            'CiperName'  = $cipher
            'KDFName'    = $kdfName
            'KDFOptions' = $val[2]
            'PublicKey'  = $pubKeys[$i]
            'PrivateKey' = $privKeys[$i]
        }
    }
}

function Get-PublicKeyImpl([byte[]]$data) {
    # 要素ごとに分割
    $val = @()
    while ($data.Length -ne 0) {
        $len = toUInt32 $data[0..3]
        $end = $len + 3
        $val += , $data[4..$end]
        if ($data.Length -eq $end + 1) {
            $data = @()
            break
        }
        $data = $data[($end + 1)..($data.Length - 1)]
    }
    $type = [System.Text.Encoding]::ASCII.GetString($val[0])

    switch ($type) {
        'ssh-rsa' {
            # exponent
            $val[1] = @(0) + $val[1]
            [array]::Reverse($val[1])
            $e = [bigint]::new($val[1])

            # bit数
            $bit = $val[2].Length * 8
            if ($val[2][0] -eq 0) {
                $bit -= 8
            }

            # modulus
            [array]::Reverse($val[2])
            $m = [bigint]::new($val[2])

            return [PSCustomObject]@{
                'Name'     = $type
                'Bit'      = $bit
                'Modulus'  = $m
                'Exponent' = $e
            }
        }
        'sk-ecdsa-sha2-nistp256@openssh.com' {
            return [PSCustomObject]@{
                'Name'        = $type
                'CurveName'   = [System.Text.Encoding]::UTF8.GetString($val[1])
                'EC_PointQ'   = $val[2]
                'Application' = [System.Text.Encoding]::UTF8.GetString($val[3])
            }
        }
        'ecdsa-sha2-nistp256' {
            return [PSCustomObject]@{
                'Name'      = $type
                'CurveName' = [System.Text.Encoding]::UTF8.GetString($val[1])
                'EC_PointQ' = $val[2]
            }
        }
        'sk-ssh-ed25519@openssh.com' {
            return [PSCustomObject]@{
                'Name'        = $type
                'PublicKey'   = $val[1]
                'Application' = [System.Text.Encoding]::UTF8.GetString($val[2])
            }
        }
        'ssh-ed25519' {
            return [PSCustomObject]@{
                'Name'      = $type
                'PublicKey' = $val[1]
            }
        }
        Default { throw "unsupported key type: $type" }
    }
}
function Get-PublicKey($file) {
    $pub_key = Get-Content $file
    $key = $pub_key -split ' '
    $type = $key[0]
    $data = $key[1]
    $comment = $key[2]
    $b = [System.Convert]::FromBase64String($data)
    $result = Get-PublicKeyImpl $b
    $result | Add-Member -MemberType NoteProperty -Name Comment -Value $comment
    return $result
}

Get-ChildItem .\testkeys -File -Filter '*.pub' | ForEach-Object {
    $publickey = $_.Name
    $privatekey = $_.BaseName
    "# $privatekey"
    try {
        Get-PublicKey "$($_.Directory)\$publickey" | Format-List
        Get-PrivateKey "$($_.Directory)\$privatekey" | Format-List
    }
    catch {
        $_ | Out-String | Write-Host -ForegroundColor Red
        $e = $_.Exception
        while ($null -ne $e.InnerException) {
            $e, $e.StackTrace | Out-String | Write-Host -ForegroundColor Red
            $e = $e.InnerException
        }
    }
}
