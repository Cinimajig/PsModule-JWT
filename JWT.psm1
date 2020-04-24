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

Function ConvertTo-Base64 {
  Param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]$InputObject,
    [Parameter()][Switch]$FromCharArray
  )

  If ($FromCharArray) {
    Return [System.Convert]::ToBase64String([char[]]$InputObject) -replace '\+', '-' -replace '/', '_' -replace '='
  }
  Else {
    Return [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($InputObject.Trim())) -replace '\+', '-' -replace '/', '_' -replace '='
  }
}

Function ConvertFrom-Base64 {
  Param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)][String]$Base64String
  )

  Return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Base64String.Trim())) -replace '\+', '-' -replace '/', '_' -replace '='
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

    $alg = "HS256"

    Switch ($Algorithm.Trim()) {
      "HS256" { $alg = "HMACSHA256" }
      "HS384" { $alg = "HMACSHA384" }
      "HS512" { $alg = "HMACSHA512" }

      Default { $alg = "HMACSHA256" }
    }

    $JsonHeaders = ConvertTo-Base64 -InputObject "{`"alg`":`"$($Algorithm.Trim())`",`"typ`":`"JWT`"}"

    If ($InputObject.GetType().Name -eq "String") {
      $JsonPayload = $InputObject.Trim()
    }
    Else {
      $JsonPayload = $InputObject | ConvertTo-Json -Compress
    }

    # If ($JsonPayload -match '\\?"exp\\?":[\d]{10,20}') {

    $Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($JsonPayload)) -replace '\+', '-' -replace '/', '_' -replace '='
    $Hash = [System.Security.Cryptography.HashAlgorithm]::Create($alg)

    If ($HmacSecret) {
      $Hash.Key = [System.Text.Encoding]::UTF8.GetBytes($HmacSecret)
    }
      
    $Signature = $Hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$JsonHeaders.$Payload")) #| ConvertTo-Base64 -FromCharArray
     
    If ($OutObject) {
      Return [JWTToken]::New($JsonHeaders, $Payload, ([System.Convert]::ToBase64String($Signature) -replace '\+', '-' -replace '/', '_' -replace '='))
    }
    Else {
      Return "$JsonHeaders.$Payload.$([System.Convert]::ToBase64String($Signature) -replace '\+', '-' -replace '/', '_' -replace '=')"
    }
    <#
    }
    Else {
      Throw "Payload does not have a exp field."
    }
    #>
  }

}

Export-ModuleMember -Function New-JWT
