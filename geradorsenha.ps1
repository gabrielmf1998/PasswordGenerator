function New-SecurePassword {
    [CmdletBinding()]
    param(
        [int]   $Length         = 32,
        [switch] $IncludeUnicode
    )

    $asciiChars = ([char[]](33..126)) -join ''
    $unicodeChars = if ($IncludeUnicode) {
        ([char[]](0x00A1..0x00FF) + (0x2200..0x22FF)) -join ''
    } else {
        ''
    }
    $charSet = ($asciiChars + $unicodeChars).ToCharArray()
    $max = $charSet.Length
# Usa função RNG descontinuada da Microsoft, mas ainda serve para gerar senhas de alta confianca!
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()

    function Get-UniformIndex {
        param([System.Security.Cryptography.RandomNumberGenerator]$Rng, [int]$Upper)
        while ($true) {
            $bytes = New-Object byte[] 4
            $Rng.GetBytes($bytes)
            $value = [BitConverter]::ToUInt32($bytes, 0)
            $limit = [uint32]([uint64]([uint32]::MaxValue + 1) - (([uint32]::MaxValue + 1) % $Upper))
            if ($value -lt $limit) {
                return [int]($value % $Upper)
            }
        }
    }

    $passwordChars = for ($i = 0; $i -lt $Length; $i++) {
        $idx = Get-UniformIndex -Rng $rng -Upper $max
        $charSet[$idx]
    }

    -join $passwordChars
}
New-SecurePassword