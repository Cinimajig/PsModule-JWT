# PsModule-JWT
A VERY basic JWT-Generator module for Powershell.

Download the module-file and then import it, where you want to use it.

```powershell
# Importing the module
Import-Module C:\MyModulePath\JWT.psm1

# Generate a JSON-token from a JSON-payload
New-JWT -InputObject '{"iss":"http://myapp.com/","sub":"users/user1234","scope":"self, admins"}' -Algorithm HS256 -HmacSecret secret

# Alternative use an hashtable/object
$Claims = @{
    iat = 1434660338
    exp = 1434663938
    nbf = 1434663938
    iss = "http://myapp.com/"
}

$Claims | New-JWT -Algorithm HS256 -HmacSecret secret

# Get-Help New-JWT
New-JWT [-InputObject] <Object> [-Algorithm] {HS256 | HS384 | HS512} [-HmacSecret] <string> [-OutObject] [<CommonParameters>]
```
