﻿#Requires -Version 3
function Get-PwnedPasteAccount
{
    <#
            .SYNOPSIS
            Report all pastes of an account via the https://haveibeenpwned.com API service.
 
            .DESCRIPTION
            Report all pastes of an account via the https://haveibeenpwned.com API service.

            This function queries the https://haveibeenpwned.com API service created by Troy Hunt (@troyhunt)
            and reports all pastres of the account along with the source and occurances. 

            .EXAMPLE
            Get-PwnedPasteAccount -EmailAdddress email@domain.com
            Retuns all pastes of the account along with the source and occurances

            .INPUTS
            None
 
            .NOTES
            Author:  Mark Ukotic
            Website: http://blog.ukotic.net
            Twitter: @originaluko
            GitHub:  https://github.com/originaluko/

            Updated 2018-12-20
            Author:  Owen Conti
            Website: http://www.code56.co.uk
            Twitter: @code_56
            GitHub:  https://github.com/sid351/

            .LINK
            https://github.com/originaluko/haveibeenpwned

    #>
    
    [CmdletBinding()]
    [OutputType([object])]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('(\w+@[]a-zA-Z_]+?\.[a-zA-Z]{2,6})')]
        [string]$EmailAddress
    )


    Begin
    {
        $URI = "https://haveibeenpwned.com/api/v2/pasteaccount/$EmailAddress"
    }
    Process
    {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        try
        {
            $Request = Invoke-RestMethod -Uri $URI
        }
         catch [System.Net.WebException] {
            Switch ($_.Exception.Message) {
                'The remote server returned an error: (400) Bad Request.' {
                    Write-Error -Message 'Bad Request - the account does not comply with an acceptable format.'
                }
                'The remote server returned an error: (403) Forbidden.' {
                    Write-Error -Message 'Forbidden - no user agent has been specified in the request.'
                }
                'The remote server returned an error: (404) Not Found.' {
                     $Response = [pscustomobject]@{
                        Id = "Not pwned"
                        Source = "Not pwned"
                        Title = "Not pwned"
                        Date = ""
                        EmailCount = 0
                    }
                }
                'The remote server returned an error: (429) Too Many Requests.' {
                    Write-Error -Message 'Too many requests - the rate limit has been exceeded.'
                }
            }
            $Response
            Return
        }
        $Request 
    }
}
