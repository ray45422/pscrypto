Set-StrictMode -Version Latest
#RFC4880

$ASN1_CURVE_IDENTIFIERS = @{
    '1.2.840.10045.3.1.7' = [PSCustomObject]@{
        'ObjectID' = '1.2.840.10045.3.1.7'
        'Name' = 'NIST P-256'
        'Data' = @(0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07)
    }
    '1.3.132.0.34' = [PSCustomObject]@{
        'ObjectID' = '1.3.132.0.34'
        'Name' = 'NIST P-384'
        'Data' = @(0x2B, 0x81, 0x04, 0x00, 0x22)
    }
    '1.3.132.0.35' = [PSCustomObject]@{
        'ObjectID' = '1.3.132.0.35'
        'Name' = 'NIST P-521'
        'Data' = @(0x2B, 0x81, 0x04, 0x00, 0x23);
    }
    '1.3.36.3.3.2.8.1.1.7' = [PSCustomObject]@{
        'ObjectID' = '1.3.36.3.3.2.8.1.1.7'
        'Name' = 'brainpoolP256r1'
        'Data' = @(0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07)
    }
    '1.3.36.3.3.2.8.1.1.13' = [PSCustomObject]@{
        'ObjectID' = '1.3.36.3.3.2.8.1.1.13'
        'Name' = 'brainpoolP512r1'
        'Data' = @(0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D)
    }
    '1.3.6.1.4.1.11591.15.1' = [PSCustomObject]@{
        'ObjectID' = '1.3.6.1.4.1.11591.15.1'
        'Name' = 'Ed25519'
        'Data' = @(0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01)
    }
    '1.3.6.1.4.1.3029.1.5.1' = [PSCustomObject]@{
        'ObjectID' = '1.3.6.1.4.1.3029.1.5.1'
        'Name' = 'Curve25519'
        'Data' = @(0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01)
    }
}

$ASN1_HASH_IDENTIFIERS = @{
    'MD5' = @(
        0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86,
        0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00,
        0x04, 0x10
    )
    'RIPEMD-160' = @(
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24,
        0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14
    )
    'SHA-1' = @(
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0E,
        0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14
    )
    'SHA2-224' = @(
        0x30, 0x2D, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
        0x00, 0x04, 0x1C
    )
    'SHA2-256' = @(
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20
    )
    'SHA2-384' = @(
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
        0x00, 0x04, 0x30
    )
    'SHA2-512' = @(
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
        0x00, 0x04, 0x40
    )
}
$ASN1_HASH_IDENTIFIERS.SHA1 = $ASN1_HASH_IDENTIFIERS.'SHA-1'
$ASN1_HASH_IDENTIFIERS.SHA224 = $ASN1_HASH_IDENTIFIERS.'SHA2-224'
$ASN1_HASH_IDENTIFIERS.SHA256 = $ASN1_HASH_IDENTIFIERS.'SHA2-256'
$ASN1_HASH_IDENTIFIERS.SHA384 = $ASN1_HASH_IDENTIFIERS.'SHA2-384'
$ASN1_HASH_IDENTIFIERS.SHA512 = $ASN1_HASH_IDENTIFIERS.'SHA2-512'

$tagTypes = @{
    # 4.3 Packet Tags
    0 = 'Reserved - a packet tag MUST NOT have this value'
    1 = 'Public-Key Encrypted Session Key Packet'
    2 = 'Signature Packet'
    3 = 'Symmetric-Key Encrypted Session Key Packet'
    4 = 'One-Pass Signature Packet'
    5 = 'Secret-Key Packet'
    6 = 'Public-Key Packet'
    7 = 'Secret-Subkey Packet'
    8 = 'Compressed Data Packet'
    9 = 'Symmetrically Encrypted Data Packet'
    10 = 'Marker Packet'
    11 = 'Literal Data Packet'
    12 = 'Trust Packet'
    13 = 'User ID Packet'
    14 = 'Public-Subkey Packet'
    17 = 'User Attribute Packet'
    18 = 'Sym. Encrypted and Integrity Protected Data Packet'
    19 = 'Modification Detection Code Packet'
    20 = 'AEAD Encrypted Data Packet'
    60 = 'Private or Experimental Values'
    61 = 'Private or Experimental Values'
    62 = 'Private or Experimental Values'
    63 = 'Private or Experimental Values'
}

$publicKeyAlgorithms = @{
    1 = 'RSA (Encrypt or Sign)'
    2 = 'RSA Encrypt-Only'
    3 = 'RSA Sign-Only'
    16 = 'Elgamal (Encrypt-Only)'
    17 = 'DSA (Digital Signature Algorithm)'
    18 = 'ECDH public key algorithm'
    19 = 'ECDSA public key algorithm'
    20 = 'Reserved (formerly Elgamal Encrypt or Sign)'
    21 = 'Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)'
    22 = 'EdDSA'
    23 = 'Reserved for AEDH'
    24 = 'Reserved for AEDSA'
    100 = 'Private/Experimental algorithm'
    101 = 'Private/Experimental algorithm'
    102 = 'Private/Experimental algorithm'
    103 = 'Private/Experimental algorithm'
    104 = 'Private/Experimental algorithm'
    105 = 'Private/Experimental algorithm'
    106 = 'Private/Experimental algorithm'
    107 = 'Private/Experimental algorithm'
    108 = 'Private/Experimental algorithm'
    109 = 'Private/Experimental algorithm'
    110 = 'Private/Experimental algorithm'
}
$symmetricKeyAlgorithms = @{
    0 = 'Plaintext or unencrypted data'
    1 = 'IDEA'
    2 = 'TripleDES (DES-EDE, - 168 bit key derived from 192)'
    3 = 'CAST5 (128 bit key, as per [RFC2144])'
    4 = 'Blowfish (128 bit key, 16 rounds)'
    5 = 'Reserved'
    6 = 'Reserved'
    7 = 'AES with 128-bit key'
    8 = 'AES with 192-bit key'
    9 = 'AES with 256-bit key'
    10 = 'Twofish with 256-bit key'
    11 = 'Camellia with 128-bit key'
    12 = 'Camellia with 192-bit key'
    13 = 'Camellia with 256-bit key'
    100 = 'Private/Experimental algorithm'
    101 = 'Private/Experimental algorithm'
    102 = 'Private/Experimental algorithm'
    103 = 'Private/Experimental algorithm'
    104 = 'Private/Experimental algorithm'
    105 = 'Private/Experimental algorithm'
    106 = 'Private/Experimental algorithm'
    107 = 'Private/Experimental algorithm'
    108 = 'Private/Experimental algorithm'
    109 = 'Private/Experimental algorithm'
    110 = 'Private/Experimental algorithm'
}
$hashAlgorithms = @{
    1 = 'MD5'
    2 = 'SHA1'
    3 = 'RIPEMD160' # RIPE-MD/160
    4 = 'Reserved'
    5 = 'Reserved'
    6 = 'Reserved'
    7 = 'Reserved'
    8 = 'SHA256' # SHA2-256
    9 = 'SHA384' # SHA2-384
    10 = 'SHA512' # SHA2-512
    11 = 'SHA224' # SHA2-224
    12 = 'SHA3-256' # SHA3-256
    13 = 'Reserved'
    14 = 'SHA3-512' # SHA3-512
    100 = 'Private/Experimental algorithm'
    101 = 'Private/Experimental algorithm'
    102 = 'Private/Experimental algorithm'
    103 = 'Private/Experimental algorithm'
    104 = 'Private/Experimental algorithm'
    105 = 'Private/Experimental algorithm'
    106 = 'Private/Experimental algorithm'
    107 = 'Private/Experimental algorithm'
    108 = 'Private/Experimental algorithm'
    109 = 'Private/Experimental algorithm'
    110 = 'Private/Experimental algorithm'
}
$compressionAlgorithms = @{
    0 = 'Uncompressed'
    1 = 'ZIP'
    2 = 'ZLIB'
    3 = 'BZip2'
    100 = 'Private/Experimental algorithm'
    101 = 'Private/Experimental algorithm'
    102 = 'Private/Experimental algorithm'
    103 = 'Private/Experimental algorithm'
    104 = 'Private/Experimental algorithm'
    105 = 'Private/Experimental algorithm'
    106 = 'Private/Experimental algorithm'
    107 = 'Private/Experimental algorithm'
    108 = 'Private/Experimental algorithm'
    109 = 'Private/Experimental algorithm'
    110 = 'Private/Experimental algorithm'
}
$signatureTypes = @{
    0x00 = 'Signature of a binary document.' # This means the signer owns it, created it, or certifies that it has not been modified.
    0x01 = 'Signature of a canonical text document.' # This means the signer owns it, created it, or certifies that it has not been modified. The signature is calculated over the text data with its line endings converted to <CR><LF>.
    0x02 = 'Standalone signature.' # This signature is a signature of only its own subpacket contents. It is calculated identically to a signature over a zero-length binary document. Note that it doesn't make sense to have a V3 standalone signature.
    0x10 = 'Generic certification of a User ID and Public-Key packet.' # The issuer of this certification does not make any particular assertion as to how well the certifier has checked that the owner of the key is in fact the person described by the User ID.
    0x11 = 'Persona certification of a User ID and Public-Key packet.' # The issuer of this certification has not done any verification of the claim that the owner of this key is the User ID specified.
    0x12 = 'Casual certification of a User ID and Public-Key packet.' # The issuer of this certification has done some casual verification of the claim of identity.
    0x13 = 'Positive certification of a User ID and Public-Key packet.' # The issuer of this certification has done substantial verification of the claim of identity. Most OpenPGP implementations make their "key signatures" as 0x10 certifications. Some implementations can issue 0x11-0x13 certifications, but few differentiate between the types.
    0x16 = 'Attested Key Signature.' # This signature is issued by the primary key over itself and its User ID (or User Attribute). It MUST contain an "Attested Certifications" subpacket and a "Signature Creation Time" subpacket. This type of key signature does not replace or override any standard certification (0x10-0x13). Only the most recent Attestation Key Signature is valid for any given <key,userid> pair. If more than one Certification Attestation Key Signature is present with the same Signature Creation Time, the set of attestations should be treated as the union of all "Attested Certifications" subpackets from all such signatures with the same timestamp.
    0x18 = 'Subkey Binding Signature.' # This signature is a statement by the top-level signing key that indicates that it owns the subkey. This signature is calculated directly on the primary key and subkey, and not on any User ID or other packets. A signature that binds a signing subkey MUST have an Embedded Signature subpacket in this binding signature that contains a 0x19 signature made by the signing subkey on the primary key and subkey.
    0x19 = 'Primary Key Binding Signature.' # This signature is a statement by a signing subkey, indicating that it is owned by the primary key and subkey. This signature is calculated the same way as a 0x18 signature: directly on the primary key and subkey, and not on any User ID or other packets.
    0x1F = 'Signature directly on a key.' # This signature is calculated directly on a key. It binds the information in the Signature subpackets to the key, and is appropriate to be used for subpackets that provide information about the key, such as the Revocation Key subpacket. It is also appropriate for statements that non-self certifiers want to make about the key itself, rather than the binding between a key and a name.
    0x20 = 'Key revocation signature.' # The signature is calculated directly on the key being revoked. A revoked key is not to be used. Only revocation signatures by the key being revoked, or by an authorized revocation key, should be considered valid revocation signatures.
    0x28 = 'Subkey revocation signature.' # The signature is calculated directly on the subkey being revoked. A revoked subkey is not to be used. Only revocation signatures by the top-level signature key that is bound to this subkey, or by an authorized revocation key, should be considered valid revocation signatures.
    0x30 = 'Certification revocation signature.' # This signature revokes an earlier User ID certification signature (signature class 0x10 through 0x13) or direct-key signature (0x1F). It should be issued by the same key that issued the revoked signature or an authorized revocation key. The signature is computed over the same data as the certificate that it revokes, and should have a later creation date than that certificate.
    0x40 = 'Timestamp signature.' # This signature is only meaningful for the timestamp contained in it.
    0x50 = 'Third-Party Confirmation signature.' # This signature is a signature over some other OpenPGP Signature packet(s). It is analogous to a notary seal on the signed data. A third-party signature SHOULD include Signature Target subpacket(s) to give easy identification. Note that we really do mean SHOULD. There are plausible uses for this (such as a blind party that only sees the signature, not the key or source document) that cannot include a target subpacket.
}
$signatureSubpacketTypes = @{
    0 = 'Reserved'
    1 = 'Reserved'
    2 = 'Signature Creation Time'
    3 = 'Signature Expiration Time'
    4 = 'Exportable Certification'
    5 = 'Trust Signature'
    6 = 'Regular Expression'
    7 = 'Revocable'
    8 = 'Reserved'
    9 = 'Key Expiration Time'
    10 = 'Placeholder for backward compatibility'
    11 = 'Preferred Symmetric Algorithms'
    12 = 'Revocation Key'
    13 = 'Reserved'
    14 = 'Reserved'
    15 = 'Reserved'
    16 = 'Issuer'
    17 = 'Reserved'
    18 = 'Reserved'
    19 = 'Reserved'
    20 = 'Notation Data'
    21 = 'Preferred Hash Algorithms'
    22 = 'Preferred Compression Algorithms'
    23 = 'Key Server Preferences'
    24 = 'Preferred Key Server'
    25 = 'Primary User ID'
    26 = 'Policy URI'
    27 = 'Key Flags'
    28 = "Signer's User ID"
    29 = 'Reason for Revocation'
    30 = 'Features'
    31 = 'Signature Target'
    32 = 'Embedded Signature'
    33 = 'Issuer Fingerprint'
    34 = 'Preferred AEAD Algorithms'
    35 = 'Intended Recipient Fingerprint'
    37 = 'Attested Certifications'
    38 = 'Key Block'
    100 = 'Private or experimental'
    101 = 'Private or experimental'
    102 = 'Private or experimental'
    103 = 'Private or experimental'
    104 = 'Private or experimental'
    105 = 'Private or experimental'
    106 = 'Private or experimental'
    107 = 'Private or experimental'
    108 = 'Private or experimental'
    109 = 'Private or experimental'
    110 = 'Private or experimental'
}
$s2kTypes = @{
    0 = 'Simple S2K'
    1 = 'Salted S2K'
    2 = 'Reserved value'
    3 = 'Iterated and salted S2K'
    100 = 'Private/experimental S2K'
    101 = 'Private/experimental S2K'
    102 = 'Private/experimental S2K'
    103 = 'Private/experimental S2K'
    104 = 'Private/experimental S2K'
    105 = 'Private/experimental S2K'
    106 = 'Private/experimental S2K'
    107 = 'Private/experimental S2K'
    108 = 'Private/experimental S2K'
    109 = 'Private/experimental S2K'
    110 = 'Private/experimental S2K'
}
[Flags()] enum KeyFlags {
    Certify               = 0x0001 # This key may be used to certify other keys.
    Sign                  = 0x0002 # This key may be used to sign data.
    EncryptCommunications = 0x0004 # This key may be used to encrypt communications.
    EncryptStorage        = 0x0008 # This key may be used to encrypt storage.
    SecretSharing         = 0x0010 # The private component of this key may have been split by a secret-sharing mechanism.
    Authentication        = 0x0020 # This key may be used for authentication.
    Possession            = 0x0080 # The private component of this key may be in the possession of more than one person.
    ADSK                  = 0x0400 # This key may be used as an additional decryption subkey (ADSK).
    Timestamping          = 0x0800 # This key may be used for timestamping.
}
[Flags()] enum KeyFeatures {
    ModificationDetection = 0x0001 # Modification Detection (packets 18 and 19)
    AEADEDP_V5SKESKP      = 0x0002 # AEAD Encrypted Data Packet (packet 20) and version 5 Symmetric-Key Encrypted Session Key Packets (packet 3)
    V5PK_NFP              = 0x0004 # Version 5 Public-Key Packet format and corresponding new fingerprint format
}
[Flags()] enum KeyServerPreferences {
    NoModify = 0x0080
}

Add-Type -TypeDefinition @'
using System;
public class PGPUtils {
    public static int CRC24(byte[] data)
    {
        int CRC24_INIT = 0x00B704CE;
        int CRC24_POLY = 0x01864CFB;
        int crc = CRC24_INIT;
        for(int i = 0; i < data.Length; i++) {
            crc ^= ((int)data[i]) << 16;
            for(int j = 0; j < 8; j++) {
                crc <<= 1;
                if((crc & 0x01000000) != 0) {
                    crc ^= CRC24_POLY;
                }
            }
        }
        return crc;
    }
}
'@

function Get-CurveInfo([byte[]]$data, $offset = 0, $length = -1) {
    if($length -eq -1) {
        $length = $data.Length - $offset
    }
    return $ASN1_CURVE_IDENTIFIERS.Values | Where-Object {$_.Data.Length -eq $length} | ForEach-Object {
        for($i = 0; $i -lt $length; $i++) {
            if($data[$offset + $i] -ne $_.Data[$i]) {
                return
            }
        }
        return $_
    }
}
function Get-DataFromHashTable($name, $table, $key) {
    if($table.ContainsKey($key)) {
        $value = $table[$key]
    } else {
        $value = "Unknown ${name}: $key"
    }
    [PSCustomObject]@{
        'Key' = $key
        'Value' = $value
    }
}
function Get-SignatureType([int]$key) {
    return Get-DataFromHashTable 'Signature' $signatureTypes $key
}

function Get-PublicKeyAlgorithm([int]$key) {
    return Get-DataFromHashTable 'PublicKey-Algorithm' $publicKeyAlgorithms $key
}

function Get-HashAlgorithm([int]$key) {
    return Get-DataFromHashTable 'Hash-Algorithm' $hashAlgorithms $key
}

function Set-DebugData($data, $offset, $len = -1) {
    if($len -eq -1) {
        $len = $data.Length - 1
    } else {
        $len += $offset - 1
    }
    if($len -gt $data.Length) {
        $len = $data.Length - 1
    }
    $data[$offset..$len] | Format-Hex | Out-String | Set-Clipboard
}

function ConvertTo-Hex($data, $large) {
    $str = ''
    if($large) {
        $format = '{0:X2}'
    } else {
        $format = '{0:x2}'
    }
    foreach($d in $data) {
        $str += $format -f $d
    }
    return $str
}
function ConvertFrom-Hex($data, $delm = '') {
    if($delm -ne '') {
        $arr = $data -split $delm
        $arr = $arr | ForEach-Object {
            "[byte]0x$_" | Invoke-Expression
        }

    } else {
        $arr = @()
        $str = $data
        while($str -ne '') {
            $x = $str.Substring(0, 2)
            $arr += "[byte]0x$x" | Invoke-Expression
            $str = $str.SubString(2)
        }
    }
    return $arr
}
function Get-Hash($packet, $algorithm, $offset = 0, $length = -1) {
    if($length -eq -1) {
        $length = $packet.Length - $offset
    }
    $hashStream = [System.IO.MemoryStream]::new();
    $hashStream.Write($packet, $offset, $length)
    $hashStream.Flush()
    $hashStream.Position = 0
    $hash = Get-HashFromStream $hashStream $algorithm
    $hashstream.Close()
    return $hash
}
function Get-HashFromStream($stream, $algorithm) {
    return Get-FileHash -InputStream $stream -Algorithm $algorithm
}

function Get-UnixTime($packet, $offset) {
    $v = $packet[$offset..($offset + 3)]
    $offset += 4
    [array]::Reverse($v)
    $time = [System.BitConverter]::ToUInt32($v, 0)
    [PSCustomObject]@{
        'Time' = $time
        'NewOffset' = $offset
    }
}

function Get-DateFromUnixTime($time) {
    [datetime]::new(1970, 1, 1).AddSeconds($time).ToLocalTime()
}

function Get-KeyData($packet, $offset) {
    $v = $packet[$offset..($offset + 1)]
    $offset += 2
    [array]::Reverse($v)
    $len = [System.BitConverter]::ToUInt16($v, 0)
    $lenB = [int][System.Math]::Ceiling($len / 8)

    $key = $packet[$offset..($offset + $lenB - 1)]
    $offset += $lenB

    [PSCustomObject]@{
        'Key' = $key
        'Length' = $len
        'NewOffset' = $offset
    }
}

function Get-UserData($packet) {
    $name = [System.Text.Encoding]::UTF8.GetString($packet.Data)
    [PSCustomObject]@{
        'TagType' = $packet.TagType
        'TagTypeName' = $packet.TagTypeName
        'Name' = $name
        'HashData' = ([byte[]]$packet.Data)
    }
}
function Get-SignatureSubpacketData($packet, $offset) {
    $p = $offset
    $data = $packet.Data
    $allLen = ([long]$data[$offset++] -shl 8) + $data[$offset++]
    $end = $allLen + $p
    $subPackets = @()
    while($offset -lt $end) {
        $v = $data[$offset++]
        if($v -lt 192) {
            $len = $v
        } elseif($v -lt 255) {
            $len = ($v - 192) -shl 8
            $len += $data[$offset++] + 192
        } else {
            $len = 0
            for($i = 0; $i -lt 4; $i++) {
                $len = $len -shl 8
                $len += $data[$offset++]
            }
        }
        if($len -eq 0) {
            continue
        }
        $type = Get-DataFromHashTable 'Signature Subpacket Type' $signatureSubpacketTypes ([int]$data[$offset++])
        $result = [PSCustomObject]@{
            'Type' = $type.Key
            'TypeName' = $type.Value
        }
        $d = $data[$offset..($offset + $len - 2)]
        switch($type.Key) {
            2 {
                $time = Get-UnixTime $data $offset
                Add-Member -InputObject $result -NotePropertyName 'CreationTime' -NotePropertyValue (Get-DateFromUnixTime $time.Time)
            }
            9 {
                $time = Get-UnixTime $d
                Add-Member -InputObject $result -NotePropertyName 'KeyExpirationTime' -NotePropertyValue $time.Time
            }
            11 {
                $list = @()
                for($i = 0; $i -lt $d.Length; $i++) {
                    $list += Get-DataFromHashTable 'SymmetricKey-Algorithm' $symmetricKeyAlgorithms ([int]$d[$i])
                }
                Add-Member -InputObject $result -NotePropertyName 'PrefferedSymmetricAlgorithms' -NotePropertyValue $list
            }
            16 {
                Add-Member -InputObject $result -NotePropertyName 'IssuerID' -NotePropertyValue (ConvertTo-Hex $d $true)
            }
            21 {
                $list = @()
                for($i = 0; $i -lt $d.Length; $i++) {
                    $list += Get-HashAlgorithm $d[$i]
                }
                Add-Member -InputObject $result -NotePropertyName 'PrefferedHashAlgorithms' -NotePropertyValue $list
            }
            22 {
                $list = @()
                for($i = 0; $i -lt $d.Length; $i++) {
                    $list += Get-DataFromHashTable 'Compression-Algorithm' $compressionAlgorithms ([int]$d[$i])
                }
                Add-Member -InputObject $result -NotePropertyName 'PrefferedCompressionAlgorithms' -NotePropertyValue $list
            }
            23 {
                [KeyServerPreferences]$flags = 0
                for($i = 0; $i -lt $d.Length; $i++) {
                    $flags += $d[$i] -shl ($i * 8)
                }
                Add-Member -InputObject $result -NotePropertyName 'KeyServerPreference' -NotePropertyValue $flags
            }
            27 {
                [KeyFlags]$flags = 0
                for($i = 0; $i -lt $d.Length; $i++) {
                    $flags += $d[$i] -shl ($i * 8)
                }
                Add-Member -InputObject $result -NotePropertyName 'KeyFlags' -NotePropertyValue $flags
            }
            30 {
                [KeyFeatures]$flags = 0
                for($i = 0; $i -lt $d.Length; $i++) {
                    $flags += $d[$i] -shl ($i * 8)
                }
                Add-Member -InputObject $result -NotePropertyName 'KeyFeatures' -NotePropertyValue $flags
            }
            32 {
                $sig = Get-SignatureData ([PSCustomObject]@{
                    'TagType' = $packet.TagType
                    'TagTypeName' = $packet.TagTypeName
                    'Data' = ([byte[]]$d)
                })
                Add-Member -InputObject $result -NotePropertyName 'Signature' -NotePropertyValue $sig
            }
            33 {
                $version = $d[0]
                if($version -eq 4) {
                    $fp = $d[1..($d.Length - 1)]
                    Add-Member -InputObject $result -NotePropertyName 'FingerPrint' -NotePropertyValue (ConvertTo-Hex $fp $true)
                }
            }
            Default {
                Add-Member -InputObject $result -NotePropertyName 'Data' -NotePropertyValue (ConvertTo-Hex $d $true)
            }
        }
        $offset += $len - 1
        $subPackets += $result
    }
    return [PSCustomObject]@{
        'Subpackets' = $subPackets
        'NewOffset' = $offset
    }
}
function Get-SignatureData($packet) {
    $pos = 0
    $hashStart = $pos
    $data = $packet.Data

    $version = $data[$pos++]
    if($version -eq 4) {

        $signatureType = Get-SignatureType $data[$pos++]

        $algorithm = Get-PublicKeyAlgorithm $data[$pos++]

        $hashAlgorithm = Get-HashAlgorithm $data[$pos++]

        $hashedSubpackets = Get-SignatureSubpacketData $packet $pos
        $pos = $hashedSubpackets.NewOffset
        $hashEnd = $pos

        $UnhashedSubpackets = Get-SignatureSubpacketData $packet $pos
        $pos = $UnhashedSubpackets.NewOffset

        $left2B = $data[$pos..($pos + 1)]
        $pos += 2
        $h = ConvertTo-Hex $left2B $true

        $hashData = $data[$hashStart..($hashEnd - $hashStart - 1)]
        $hashDataLen = $hashData.Length
        $hashData += [byte]0x04
        $hashData += [byte]0xff
        $hashData += [byte](($hashDataLen -shr 24) -band 0xff)
        $hashData += [byte](($hashDataLen -shr 16) -band 0xff)
        $hashData += [byte](($hashDataLen -shr 8) -band 0xff)
        $hashData += [byte]($hashDataLen -band 0xff)

        $sigD = Get-KeyData $data $pos
        $sig = $sigD.Key
        $sigLen = $sigD.Length
        $pos = $sigD.NewOffset
        return [PSCustomObject]@{
            'TagType' = $packet.TagType
            'TagTypeName' = $packet.TagTypeName
            'Version' = 4
            'SignatureType' = $signatureType
            'Algorithm' = $algorithm
            'HashAlgorithm' = $hashAlgorithm
            'HashedSubpacket' = $hashedSubpackets.Subpackets
            'Subpacket' = $UnhashedSubpackets.Subpackets
            'Hash16' = $h
            'HashData' = ([byte[]]$hashData)
            'Signature' = ([byte[]]$sig)
            'SignatureLength' = $sigLen
        }
    } elseif($version -eq 3) {
        $len = $data[$pos++]
        if($len -ne 5) {
            throw "Material length must be 5"
        }
        $sigType = $data[$pos++]
        $keyID = $data[$pos..($pos + 7)]
        $pos += 8
    } else {
        throw 'Unknown Signature Version: ' + $version
    }
    return $packet
}
function Get-PublicKeyDataImpl($packet) {
    $result = $null
    $pos = 0
    $data = $packet.Data
    $version = $data[$pos++]
    if($version -eq 4) {
        $timeD = Get-UnixTime $data $pos
        $creationTime = Get-DateFromUnixTime $timeD.Time
        $pos = $timeD.NewOffset

        $algorithm = Get-DataFromHashTable 'Algorithm' $publicKeyAlgorithms ([int]$data[$pos++])

        $result = [PSCustomObject]@{
            'TagType' = $packet.TagType
            'TagTypeName' = $packet.TagTypeName
            'Version' = $version
            'CreationTime' = $creationTime
            'Algorithm' = $algorithm
        }

        switch ($algorithm.Key) {
            1 {
                $keyD = Get-KeyData $data $pos
                $key = $keyD.Key
                $keyLen = $keyD.Length
                $pos = $keyD.NewOffset

                $keyD = Get-KeyData $data $pos
                $exp = $keyD.Key
                $expLen = $keyD.Length
                $pos = $keyD.NewOffset

                Add-Member -InputObject $result -NotePropertyName 'PublicKey' -NotePropertyValue ([byte[]]$key)
                Add-Member -InputObject $result -NotePropertyName 'PublicKeyLength' -NotePropertyValue $keyLen
                Add-Member -InputObject $result -NotePropertyName 'Exponent' -NotePropertyValue ([byte[]]$exp)
                Add-Member -InputObject $result -NotePropertyName 'ExponentLength' -NotePropertyValue $expLen
            }
            16 {
                # Elgamal (Encrypt-Only)
                "Algorithm Elgamal (Encrypt-Only) is not Implemented" | Write-Verbose
            }
            17 {
                # DSA
                "Algorithm DSA is not Implemented" | Write-Verbose
            }
            {@(18, 22) -contains $_} {
                $oidLen = $data[$pos++]
                $oid = $data[$pos..($pos + $oidLen - 1)]
                $pos += $oidLen
                $curve = Get-CurveInfo $oid 0 $oidLen

                $pubLen = ([int]$data[$pos++] -shl 8) + $data[$pos++]
                $pubLenB = [int][System.Math]::Ceiling($pubLen / 8)
                $pub = $data[$pos..($pos + $pubLenB - 1)]
                $pos += $pubLenB

                Add-Member -InputObject $result -NotePropertyName 'OID' -NotePropertyValue ([byte[]]$oid)
                Add-Member -InputObject $result -NotePropertyName 'OIDLength' -NotePropertyValue $oidLen
                Add-Member -InputObject $result -NotePropertyName 'CurveInfo' -NotePropertyValue $curve
                Add-Member -InputObject $result -NotePropertyName 'PublicKey' -NotePropertyValue ([byte[]]$pub)
                Add-Member -InputObject $result -NotePropertyName 'PublicKeyLength' -NotePropertyValue $pubLen
            }
            18 {
                #先に上のブロックで処理をした後に実行する
                $kdfLen = $data[$pos++]
                if($data[$pos++] -ne 1) {
                    throw 'Invalid value'
                }
                $hashAlgo = Get-HashAlgorithm $data[$pos++]
                $symAlgo = Get-DataFromHashTable 'SymmetricKey-Algorithm' $symmetricKeyAlgorithms ([int]$data[$pos++])

                Add-Member -InputObject $result -NotePropertyName 'KDFLength' -NotePropertyValue $kdfLen
                Add-Member -InputObject $result -NotePropertyName 'HashAlgorithm' -NotePropertyValue $hashAlgo
                Add-Member -InputObject $result -NotePropertyName 'SymmetricKeyAlgorithm' -NotePropertyValue $symAlgo
            }
            20 {
                # DSA
                "Algorithm DSA is not Implemented" | Write-Verbose
            }
            Default {
                throw "Not implemented Algorithm $($algorithm.Key): $($algorithm.Value)"
            }
        }

        $hashData = $data[0..($pos - 1)]
        $fp = @(0x99)
        $len = $hashData.Length
        for($i = 1; $i -ge 0; $i--) {
            $fp += [byte](($len -shr (8 * $i)) -band 0xff)
        }
        $fp += $hashData
        $fp = Get-Hash $fp 'SHA1'

        Add-Member -InputObject $result -NotePropertyName 'HashData' -NotePropertyValue ([byte[]]$hashData)
        Add-Member -InputObject $result -NotePropertyName 'FingerPrint' -NotePropertyValue $fp.Hash
        Add-Member -InputObject $result -NotePropertyName 'KeyID' -NotePropertyValue $fp.Hash.SubString($fp.Hash.Length - 16, 16)
    } else {
        throw 'Unknown Public Key Version: ' + $version
    }
    return [PSCustomObject]@{
        'Value' = $result
        'NewOffset' = $pos
    }
}
function Get-PublicKeyData($packet) {
    return (Get-PublicKeyDataImpl $packet).Value
}
function Get-SecretKeyData($packet) {
    $data = $packet.Data
    $pubKeyD = Get-PublicKeyDataImpl $packet
    $result = $pubKeyD.Value
    $pos = $pubKeyD.NewOffset
    if($result.Version -eq 4) {
        switch ($result.Algorithm.Key) {
            1 {
                $stku = $data[$pos++]
                if($stku -ne 0) {
                }

                $keyD = Get-KeyData $data $pos
                $d = $keyD.Key
                $dLen = $keyD.Length
                $pos = $keyD.NewOffset
                Add-Member -InputObject $result -NotePropertyName 'PrivateKey' -NotePropertyValue ([byte[]]$d)
                Add-Member -InputObject $result -NotePropertyName 'PrivateKeyLength' -NotePropertyValue $dLen

                $keyD = Get-KeyData $data $pos
                $p = $keyD.Key
                $pLen = $keyD.Length
                $pos = $keyD.NewOffset
                Add-Member -InputObject $result -NotePropertyName 'Prime1' -NotePropertyValue ([byte[]]$p)
                Add-Member -InputObject $result -NotePropertyName 'Prime1Length' -NotePropertyValue $pLen

                $keyD = Get-KeyData $data $pos
                $q = $keyD.Key
                $qLen = $keyD.Length
                $pos = $keyD.NewOffset
                Add-Member -InputObject $result -NotePropertyName 'Prime2' -NotePropertyValue ([byte[]]$q)
                Add-Member -InputObject $result -NotePropertyName 'Prime2Length' -NotePropertyValue $qLen

                $keyD = Get-KeyData $data $pos
                $u = $keyD.Key
                $uLen = $keyD.Length
                $pos = $keyD.NewOffset
                Add-Member -InputObject $result -NotePropertyName 'U' -NotePropertyValue ([byte[]]$u)
                Add-Member -InputObject $result -NotePropertyName 'ULength' -NotePropertyValue $uLen
            }
            18 {
                $remain = $data[$pos..($data.Length - 1)]
                Add-Member -InputObject $result -NotePropertyName 'Data' -NotePropertyValue ([byte[]]$remain)
            }
            22 {
                $remain = $data[$pos..($data.Length - 1)]
                Add-Member -InputObject $result -NotePropertyName 'Data' -NotePropertyValue ([byte[]]$remain)
            }
            Default {
                throw "Not implemented Algorithm $($algorithm.Key): $($algorithm.Value)"
            }
        }
        return $result
    } else {
        throw 'Unknown Public Key Version: ' + $version
    }
}
function Get-CompressedData($packet) {
    $algorithm = Get-DataFromHashTable 'Compression-Algorithm' $compressionAlgorithms ([int]$packet.Data[0])
    if($algorithm.Key -eq 1) {
        $ms = [System.IO.MemoryStream]::new($packet.Data, 1, $packet.Data.Length - 1)
        $outStream = [System.IO.MemoryStream]::new()
        $ds = [System.IO.Compression.DeflateStream]::new($ms, [System.IO.Compression.CompressionMode]::Decompress)
        $ds.CopyTo($outStream)
        $ms.Close()
        $ds.Close()
        $data = $outStream.ToArray()
        $outStream.Close()
        Get-PacketData $data
    }
}
function Get-LiteralData($packet) {
    $pos = 0
    $data = $packet.Data
    [char]$type = $data[$pos++]
    $len = $data[$pos++]
    $nameBuf = [byte[]]::new($len)
    for($i = 0; $i -lt $len; $i++) {
        $nameBuf[$i] = $data[$pos++]
    }
    $name = [System.Text.Encoding]::UTF8.GetString($nameBuf)
    $time = Get-UnixTime $data $pos
    $pos = $time.NewOffset
    $time = Get-DateFromUnixTime $time.Time
    $data = $data[$pos..($data.Length - 1)]
    switch($type) {
        'b' {
            # binary
            $text = [System.Text.Encoding]::UTF8.GetString($data)
            return [PSCustomObject]@{
                'TagType' = $packet.TagType
                'TagTypeName' = $packet.TagTypeName
                'FileName' = $name
                'Time' = $time
                'BinaryData' = ([byte[]]$data)
            }
        }
        't' {
            # text
            $text = [System.Text.Encoding]::Default.GetString($data)
            return [PSCustomObject]@{
                'TagType' = $packet.TagType
                'TagTypeName' = $packet.TagTypeName
                'FileName' = $name
                'Time' = $time
                'Text' = $text
            }
        }
        'u' {
            # UTF-8 Text
            $text = [System.Text.Encoding]::UTF8.GetString($data)
            return [PSCustomObject]@{
                'TagType' = $packet.TagType
                'TagTypeName' = $packet.TagTypeName
                'FileName' = $name
                'Time' = $time
                'Text' = $text
            }
        }
        'm' {
            # MIME Message
            return [PSCustomObject]@{
                'TagType' = $packet.TagType
                'TagTypeName' = $packet.TagTypeName
                'FileName' = $name
                'MIMEMessage' = ([byte[]]$data)
            }
        }
    }
}
function Get-OnePassSignaturePacket($packet) {
    $pos = 0
    $data = $packet.Data
    $version = $data[$pos++]
    $type = Get-SignatureType $data[$pos++]
    $hashAlg = Get-HashAlgorithm $data[$pos++]
    $pubAlg = Get-PublicKeyAlgorithm $data[$pos++]
    $keyId = $data[$pos..($pos + 7)]
    $pos += 8
    $isNest = $data[$pos++]

    return [PSCustomObject]@{
        'TagType' = $packet.TagType
        'TagTypeName' = $packet.TagTypeName
        'Version' = $version
        'SignatureType' = $type
        'PublicKeyAlgorithm' = $pubAlg
        'HashAlgorithm' = $hashAlg
        'KeyID' = ConvertTo-Hex $keyId $true
        'IsNest' = $isNest
        'Data' = ([byte[]]$data)
    }
}

function Get-PublicKeyEncryptedSessionKeyPacketData($packet) {
    $pos = 0
    $data = $packet.Data
    $version = $data[$pos++]
    if($version -ne 3) {
        throw "not defined version: $version"
    }
    $keyId = ConvertTo-Hex $data[$pos..($pos + 7)] $true
    $pos += 8
    $pkAlgo = Get-PublicKeyAlgorithm $data[$pos++]
    $result = [PSCustomObject]@{
        'TagType' = $packet.TagType
        'TagTypeName' = $packet.TagTypeName
        'Version' = $version
        'KeyID' = $keyId
        'PublicKeyAlgorithm' = $pkAlgo
    }
    if($pkAlgo.Key -eq 1) {
        # RSA
        $encD = Get-KeyData $data $pos
        Add-Member -InputObject $result -NotePropertyName 'EncryptedSessionKey' -NotePropertyValue ([byte[]]$encD.Key)
        Add-Member -InputObject $result -NotePropertyName 'EncryptedSessionKeyLength' -NotePropertyValue $encD.Length
    } else {
        $enc = $data[$pos..($data.Length - 1)]
        Add-Member -InputObject $result -NotePropertyName 'EncryptedSessionKey' -NotePropertyValue ([byte[]]$enc)

    }
    return $result
}
function Get-SymmetricEncryptedIntegrityProtectPacketData($packet) {
    $pos = 0
    $data = $packet.Data
    $version = $data[$pos++]
    if($version -ne 1) {
        throw "Invalid version: $version"
    }
    $enc = $data[$pos..($data.Length - 1)]
    $pos = $data.Length
    return [PSCustomObject]@{
        'TagType' = $packet.TagType
        'TagTypeName' = $packet.TagTypeName
        'Version' = $version
        'EncryptedData' = ([byte[]]$enc)
    }
}
function Get-SymmetricKeyEncryptedSessionKeyPacketData($packet) {
    $pos = 0
    $data = $packet.Data
    $version = $data[$pos++]
    if($version -ne 4) {
        throw "Undefined version $version"
    }
    $symAlgo = Get-DataFromHashTable 'SymmetricKey-Algorithm' $symmetricKeyAlgorithms ([int]$data[$pos++])

    $result = [PSCustomObject]@{
        'TagType' = $packet.TagType
        'TagTypeName' = $packet.TagTypeName
        'Version' = $version
        'SymmetricKeyAlgorithm' = $symAlgo
    }
    $s2kspec = Get-DataFromHashTable 'String-To-Key' $s2kTypes ([int]$data[$pos++])

    switch ($s2kspec.Key) {
        3 {
            $hashAlgo = Get-HashAlgorithm $data[$pos++]
            $salt = $data[$pos..($pos + 7)]
            $pos += 8
            $c = $data[$pos++]
            $count = (16 + ($c -band 15)) -shl (($c -shr 4) + 6)
            $s2k = [PSCustomObject]@{
                'Type' = $s2kspec
                'HashAlgorithm' = $hashAlgo
                'Salt' = ([byte[]]$salt)
                'Count' = $count
            }
            Add-Member -InputObject $result -NotePropertyName 'StringToKey' -NotePropertyValue $s2k
        }
        Default {
            throw "Not implemented String-To-Key Type $($s2kspec.Key): $($s2kspec.Value)"
        }
    }
    $sesKey = $data[$pos..($data.Length - 1)]
    Add-Member -InputObject $result -NotePropertyName 'SessionKey' -NotePropertyValue $sesKey
    return $result
}
function Get-PacketDataDetail($packet) {
    $type = $packet.TagType
    switch ($type) {
        1 { return Get-PublicKeyEncryptedSessionKeyPacketData $packet }
        2 { return Get-SignatureData $packet }
        3 { return Get-SymmetricKeyEncryptedSessionKeyPacketData $packet }
        4 { return Get-OnePassSignaturePacket $packet }
        5 { return Get-SecretKeyData $packet }
        6 { return Get-PublicKeyData $packet }
        7 { return Get-SecretKeyData $packet }
        8 { return Get-CompressedData $packet }
        11 { return Get-LiteralData $packet }
        13 { return Get-UserData $packet }
        14 { return Get-PublicKeyData $packet }
        18 { return Get-SymmetricEncryptedIntegrityProtectPacketData $packet}
        Default { Write-Verbose "Unknown Packet Type ${type}: $($packet.TagTypeName)" }
    }
    return $packet
}

function Get-PacketData($packet) {
    $pos = 0
    while($pos -lt $packet.Length) {
        $header = $packet[$pos++]
        if(($header -band 128) -eq 0) {
            throw 'invalid header!'
        }
        $headerType = ($header -band 0b01000000) -shr 6
        $isPartial = $false
        if($headerType -eq 0) {
            # 4.2.1 古い形式のパケット
            $packetTag = ($header -band 0b00111100) -shr 2
            $lenType = $header -band 0b00000011
            switch ($lenType) {
                0 {
                    $len = $packet[$pos++]
                }
                1 {
                    $len = ([long]$packet[$pos++]) -shl 8
                    $len += $packet[$pos++]
                }
                2 {
                    $len = ([long]$packet[$pos++]) -shl 24
                    $len += ([long]$packet[$pos++]) -shl 16
                    $len += ([long]$packet[$pos++]) -shl 8
                    $len += $packet[$pos++]
                }
                3 {
                    $len = $packet.Length - 1
                }
            }
        } else {
            $packetTag = $header -band 0b00111111
            # 4.2.1 新しい形式のパケット
            [long]$len = $packet[$pos++]
            if($len -eq 255) {
                $len = ([long]$packet[$pos++]) -shl 24
                $len += ([long]$packet[$pos++]) -shl 16
                $len += ([long]$packet[$pos++]) -shl 8
                $len += $packet[$pos++]
            } elseif($len -ge 224) {
                $isPartial = $true
                $len = $len -band 0x1F
                $len = 1 -shl $len
            } elseif($len -ge 192) {
                $len = ($len - 192)
                $len = $len -shl 8
                $len += $packet[$pos++] + 192
            }
        }
        $data = $packet[$pos..($pos + $len - 1)]
        $pos += $len
        while($isPartial) {
            $isPartial = $false
            [long]$len = $packet[$pos++]
            if($len -eq 255) {
                $len = ([long]$packet[$pos++]) -shl 24
                $len += ([long]$packet[$pos++]) -shl 16
                $len += ([long]$packet[$pos++]) -shl 8
                $len += $packet[$pos++]
            } elseif($len -ge 224) {
                $isPartial = $true
                $len = $len -band 0x1F
                $len = 1 -shl $len
            } elseif($len -ge 192) {
                $len = ($len - 192)
                $len = $len -shl 8
                $len += $packet[$pos++] + 192
            }
            $data += $packet[$pos..($pos + $len - 1)]
            $pos += $len
        }
        $tagType = Get-DataFromHashTable 'Packet-Tag' $tagTypes $packetTag
        Get-PacketDataDetail ([PSCustomObject]@{
            'TagTypeName' = $tagType.Value
            'TagType' = $packetTag
            'Data' = $data
        })
    }
}

function Get-OpenPGPPacket($file) {
    $armorHeader = @(
        '-----BEGIN PGP MESSAGE-----'
        '-----BEGIN PGP PUBLIC KEY BLOCK-----'
        '-----BEGIN PGP PRIVATE KEY BLOCK-----'
        #'-----BEGIN PGP MESSAGE, PART X/Y'
        #'-----BEGIN PGP MESSAGE, PART X-----'
        '-----BEGIN PGP SIGNATURE-----'
    )
    $armorTail = ''
    $data = Get-Content $file
    $isBinary = $true
    foreach($h in $armorHeader) {
        if($data -contains $h) {
            $isBinary = $false
            break
        }
    }
    if($isBinary) {
        $packetData = Get-Content $file -AsByteStream
        $packetData = Get-PacketData $packetData
        [PSCustomObject]@{
            'Packet' = $packetData
        }
    } else {
        $importKey = $false
        $importHead = $false
        $header = @()
        $packet = [System.Text.StringBuilder]::new($data.Length * 66)
        $checkSum = $null
        foreach($l in $data) {
            if($armorHeader -contains $l) {
                $importHead = $true
                $armorTail = ($armorHeader | Where-Object {$_ -eq $l}) -replace '-----BEGIN', '-----END'
                continue
            }
            if($importHead) {
                if($l.Trim() -eq '') {
                    $importHead = $false
                    $importKey = $true
                    continue
                }
                $header += $l
            }
            if($importKey) {
                if($l -match '^=') {
                    $importKey = $false
                    $checkSum = $l
                    continue
                }
                $null = $packet.Append($l)
            }
            if($l -eq $armorTail) {
                break
            }
        }
        $packetData = [System.Convert]::FromBase64String($packet.ToString())
        <#
        [Int32]$CRC24_INIT = 0x00B704CE
        [Int32]$CRC24_POLY = 0x01864CFB
        [Int32]$crc = $CRC24_INIT
        for($i = 0; $i -lt $packetData.Length; $i++) {
            $t = ([Int32]$packetData[$i]) -shl 16
            $crc = $crc -bxor $t
            for($j = 0; $j -lt 8; $j++) {
                $crc = $crc -shl 1
                if(($crc -band 0x1000000) -ne 0) {
                    $crc = $crc -bxor $CRC24_POLY
                }
            }
        }
        $crc = $crc -band 0xFFFFFF
        #>
        $crc = [PGPUtils]::CRC24($packetData)
        $checkSum = [System.Convert]::FromBase64String($checkSum.Substring(1))
        [array]::Reverse($checkSum)
        $checkSum += 0
        $checkSum = [System.BitConverter]::ToInt32($checkSum, 0)
        if($crc -ne $checkSum) {
            throw "Checksum not match! $crc excepted $checkSum"
        }
        $packetData = Get-PacketData $packetData
        [PSCustomObject]@{
            'Header' = $header
            'Packet' = $packetData
        }
    }
}
function Get-SignatureHash([byte[]]$data, $sign) {
    $hash1 = $data
    $hash2 = $sign.HashData
    $hashData = $hash1 + $hash2
    $hash = Get-Hash $hashData $sign.HashAlgorithm.Value
    $hash.Hash
}
function Get-SignatureHashFromStream([System.IO.Stream]$stream, $sign) {
    $memStream = [System.IO.MemoryStream]::new($stream.Length + $sign.HashData.Length)
    $stream.CopyTo($memStream)
    $memStream.Write($sign.HashData, 0, $sign.HashData.Length)
    $memStream.Position = 0
    $hash = Get-HashFromStream $memStream $sign.HashAlgorithm.Value
    $memStream.Close()
    $hash.Hash
}
function ConvertTo-ASN1([byte[]]$hash, [string]$algo, [long]$length) {
    $sigLen = $length
    [byte[]]$sig = $ASN1_HASH_IDENTIFIERS.$algo + $hash
    [byte[]]$sigPad = @(0x00, 0x01)
    for($i = 2; $i -lt ($sigLen - $sig.Length - 1); $i++) {
        $sigPad += [byte]0xff
    }
    $sigPad += [byte]0x00
    $sig = $sigPad + $sig
    return $sig
}
function ConvertFrom-ASN1([byte[]]$asn1) {
    $pos = 0
    if($asn1[$pos++] -ne 0x00) {
        $pos--
    }
    if($asn1[$pos++] -ne 0x01) {
        throw 'Invalid format!'
    }
    while($asn1[$pos++] -eq 0xff){}
    $algo = $null
    foreach($key in $ASN1_HASH_IDENTIFIERS.Keys) {
        $b = $ASN1_HASH_IDENTIFIERS.$key
        $r = $true
        for($i = 0; $i -lt $b.Length; $i++) {
            if($asn1[$pos + $i] -ne $b[$i]) {
                $r = $false
                break
            }
        }
        if($r) {
            $algo = $key
            $pos += $b.Length
            break
        }
    }
    $hash = $asn1[$pos..($asn1.Length - 1)]
    [PSCustomObject]@{
        'HashAlgorithm' = $algo
        'Hash' = $hash
    }
}

function ConvertFrom-PKCS1_v1_5([byte[]]$data) {
    $pos = 0
    if($data[$pos++] -ne 0x00 -or $data[$pos++] -ne 0x02) {
        throw 'Invalid Header'
    }
    while($data[$pos++] -ne 0x00) {
    }
    return $data[$pos..($data.Length - 1)]
}

function Get-SessionInfo($session, $key) {
    $pkcs1 = $key.Decrypt($session.EncryptedSessionKey)
    $data = ConvertFrom-PKCS1_v1_5 $pkcs1
    $pos = 0
    $pkAlgo = Get-PublicKeyAlgorithm $data[$pos++]
    $sessionKey = $data[$pos..($data.Length - 3)]
    $sum = 0
    for($i = 0; $i -lt $sessionKey.Length; $i++) {
        $sum += $sessionKey[$i]
    }
    $sum = $sum -band 0xffff
    $checkSum = (([int]$data[$pos++]) -shl 8) + $data[$pos++]
    $result = [PSCustomObject]@{
        'PublicKeyAlgorithm' = $pkAlgo
    }
}
