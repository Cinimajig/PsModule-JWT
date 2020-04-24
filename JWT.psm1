<#
  Version 1.1
  https://github.com/Cinimajig/PsModule-JWT
#>

class JWTToken {

  [String]$Header
  [String]$payload
  [String]$Signature

  JWTToken([String]$Header, [String]$payload, [String]$Signature) {
    $this.Header = $Header
    $this.payload = $payload
    $this.Signature = $Signature
  }

  [String] ToString() {
    return $this.ToJWTString()
  }

  [String] ToJWTString() {
    return "$($this.Header).$($this.payload).$($this.Signature)"
  }
}

Function New-JWT {
  Param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, HelpMessage = "Dictionary, Object or Hashtable")][ValidateNotNullOrEmpty()]$InputObject,
    [Parameter(Mandatory = $true)][ValidateSet("HS256", "HS384", "HS512")][String]$Algorithm,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][String]$HmacSecret,
    [Parameter(Mandatory = $false)][Switch]$OutObject
  )

  Begin {
    If ($null -ne $PSBoundParameters.HmacSecret -and $PSBoundParameters.HmacSecret -eq "") {
      Throw "Secret is not defined."
    }
  }

  Process {
    
    $HmacSecret = $PSBoundParameters.HmacSecret

    $alg = Switch ($Algorithm.Trim()) {
      "HS256" { "HMACSHA256" }
      "HS384" { "HMACSHA384" }
      "HS512" { "HMACSHA512" }

      Default { "HMACSHA256" }
    }

    $JsonHeaders = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("{`"alg`":`"$($Algorithm.Trim())`",`"typ`":`"JWT`"}")) -replace '\+', '-' -replace '/', '_' -replace '='

    If ($InputObject.GetType().Name -eq "String") {
      $JsonPayload = $InputObject.Trim()
    }
    Else {
      $JsonPayload = $InputObject | ConvertTo-Json -Compress
    }

    $Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($JsonPayload)) -replace '\+', '-' -replace '/', '_' -replace '='
    $Hash = [System.Security.Cryptography.HashAlgorithm]::Create($alg)

    If ($HmacSecret) {
      $Hash.Key = [System.Text.Encoding]::UTF8.GetBytes($HmacSecret)
    }
      
    $Signature = $Hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$JsonHeaders.$Payload"))
     
    If ($OutObject) {
      Return [JWTToken]::New($JsonHeaders, $Payload, ([System.Convert]::ToBase64String($Signature) -replace '\+', '-' -replace '/', '_' -replace '='))
    }
    Else {
      Return "$JsonHeaders.$Payload.$([System.Convert]::ToBase64String($Signature) -replace '\+', '-' -replace '/', '_' -replace '=')"
    }
  }

}

Export-ModuleMember -Function New-JWT
