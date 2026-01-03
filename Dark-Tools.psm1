#region ConvertFrom-CanonicalUser
function ConvertFrom-CanonicalUser {
    <#
    .SYNOPSIS
        Converts a canonical user name to Distinguished Name (DN) format.
    .DESCRIPTION
        Converts a canonical name format to LDAP Distinguished Name (DN) format. Takes a canonical name string (e.g., "example.com/OU/User") and converts it to DN format (e.g., "CN=User,OU=OU,DC=example,DC=com").
    .PARAMETER CanonicalName
        Specifies the canonical name to convert. Accepts pipeline input.
    .OUTPUTS
        Returns the Distinguished Name string.
    .EXAMPLE
        ConvertFrom-CanonicalUser -CanonicalName "example.com/admin/john.smith"
        Returns: CN=john.smith,OU=admin,DC=example,DC=com
    .EXAMPLE
        "company.org/departments/it/engineer" | ConvertFrom-CanonicalUser
        Returns: CN=engineer,OU=it,OU=departments,DC=company,DC=org
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$CanonicalName
    )
    process {
        $obj = $CanonicalName.Replace(',','\,').Split('/')
        [string]$DN = "CN=" + $obj[$obj.count - 1]
        for ($i = $obj.count - 2;$i -ge 1;$i--){$DN += ",OU=" + $obj[$i]}
        $obj[0].split(".") | ForEach-Object { $DN += ",DC=" + $_}
        return $DN
    }
}
#endregion ConvertFrom-CanonicalUser

#region ConvertFrom-DistinguishedName
function ConvertFrom-DistinguishedName {
	<#
	.SYNOPSIS
		Converts a Distinguished Name (DN) to canonical name format.
	.DESCRIPTION
		Converts an LDAP Distinguished Name (DN) format to canonical name format. Takes a DN string (e.g., "CN=User,OU=OU,DC=example,DC=com") and converts it to canonical format (e.g., "example.com/OU/User").
	.PARAMETER DistinguishedName
		Specifies the Distinguished Name to convert. Accepts pipeline input and supports arrays of strings.
	.OUTPUTS
		Returns the canonical name string.
	.EXAMPLE
		ConvertFrom-DistinguishedName -DistinguishedName "CN=john.smith,OU=admin,DC=example,DC=com"
		Returns: example.com/admin/john.smith
	.EXAMPLE
		"CN=engineer,OU=it,OU=departments,DC=company,DC=org" | ConvertFrom-DistinguishedName
		Returns: company.org/departments/it/engineer
	.EXAMPLE
		ConvertFrom-DistinguishedName -DistinguishedName "CN=user1,OU=staff,DC=domain,DC=local", "CN=user2,OU=admin,DC=domain,DC=local"
		Returns: domain.local/staff/user1 and domain.local/admin/user2
	#>
	[cmdletbinding()]
	param(
		[Parameter(Mandatory, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
		[ValidateNotNullOrEmpty()]
		[string[]]$DistinguishedName
	)
	process {
		foreach ($DN in $DistinguishedName) {
			Write-Verbose $DN
			$CanonNameSlug = ''
			$DC = ''
			foreach ( $item in ($DN.replace('\,', '~').split(','))) {
				if ( $item -notmatch 'DC=') {
					$CanonNameSlug = $item.Substring(3) + '/' + $CanonNameSlug
				}
				else {
					$DC += $item.Replace('DC=', ''); $DC += '.'
				}
			}
			$CanonicalName = $DC.Trim('.') + '/' + $CanonNameSlug.Replace('~', '\,').Trim('/')
			return $CanonicalName;
		}
	}
}

function Format-MacAddress {
    <#
    .SYNOPSIS
        Function to do a cleanup of a MACAddress string
    .DESCRIPTION
        Cleanup a MACAddress string and optionally format it with separators
    .PARAMETER MacAddress
        Specifies the MacAddress. Either a single string or an array of strings. Aliased to 'Address'
    .PARAMETER Separator
        Specifies the separator every X characters. Aliased to 'Delimiter'. Validated against set(':', 'None', '.', "-", ' ', 'Space', ';')
    .PARAMETER Case
        Specifies if the output is to be set in a particular case
        Upper Sets to upper case, 'a' becomes 'A'
        Uppercase Sets to upper case, 'a' becomes 'A'
        Lower Sets to lower case, 'A' becomes 'a'
        Lowercase Sets to lower case, 'A' becomes 'a'
        Ignore Does nothing to the case of the letters 'aB', so remains as 'aB'
    .PARAMETER Split
        Specifies how many characters to split the MacAddress on. Valid values are 2,3,4,6
    .EXAMPLE
        Format-MacAddress -MacAddress 1234567890ab
        12:34:56:78:90:ab
    .EXAMPLE
        Format-MacAddress -MacAddress '00:11:22:dD:ee:FF' -Case Upper
        00:11:22:DD:EE:FF
    .EXAMPLE
        Format-MacAddress -MacAddress '00:11:22:dD:ee:FF' -Case Lowercase
        001122ddeeff
    .EXAMPLE
        Format-MacAddress -MacAddress '00:11:22:dD:ee:FF' -Case Lowercase -Separator '-'
        00-11-22-dd-ee-ff
    .EXAMPLE
        Format-MacAddress -MacAddress '00:11:22:dD:ee:FF' -Case Lowercase -Separator '.'
        00.11.22.dd.ee.ff
    .EXAMPLE
        Format-MacAddress -Address '00:11:22:dD:ee:FF', '10005a123456' -case Uppercase -Delimiter '-'
        00-11-22-DD-EE-FF
        10-00-5A-12-34-56
        Showing how function can take an array of MacAddress using the alias 'Address' and the alias 'Delimiter' for the 'Separator' parameter
    .EXAMPLE
        '00:11:22:dD:ee:FF', '10005a123456' | Format-MacAddress -case Lowercase -Separator '.'
        00.11.22.dd.ee.ff
        10.00.5a.12.34.56
        Showing how the values for MacAddress can be received from the pipeline
    .EXAMPLE
        Format-MacAddress '10005a123456' -case Lowercase -Separator ':'
        10:00:5a:12:34:56
        Showing how MacAddress can be unnamed positional parameter
    .EXAMPLE
        '00:11:22:dD:ee:FF' | Format-MacAddress -Separator None -Case Ignore
        001122dDeeFF
    .EXAMPLE
        '00:11:22:dD:ee:FF', '10005a123456' | Format-MacAddress -case Lowercase -Separator '.' -Split 4
        0011.22dd.eeff
        1000.5a12.3456
    .EXAMPLE
        '00:11:22:dD:ee:FF', '10005a123456' | Format-MacAddress -case Lowercase -Separator '.' -Split 4 -IncludeOriginal
        OriginalMac FormattedMac
        ----------- ------------
        00:11:22:dD:ee:FF 0011.22dd.eeff
        10005a123456 1000.5a12.3456
    .OUTPUTS
        System.String
    .NOTES
        # Inspired and based on Clean-MacAddress.ps1 by Francois-Xavier www.lazywinadmin.com
        #
        # Daniel Ravnholt
        # Dark@rn.dk
        Modified:
        First RN release
    #>
    #region Parameter
    [OutputType('String')]
    [CmdletBinding()]
    param (
        [Parameter(Position=0, HelpMessage='Please enter a MAC address (12 hex)', Mandatory, ValueFromPipeline)]
        [Alias('Address')]
        [String[]] $MacAddress,
        
        [ValidateSet(':', 'None', '.', '-', ' ', 'Space', ';')]
        [Alias('Delimiter')]
        [string] $Separator = ':',
        
        [ValidateSet('Ignore', 'Upper', 'Uppercase', 'Lower', 'Lowercase')]
        [string] $Case = 'Lower',
        
        [ValidateSet(2,3,4,6)]
        [int] $Split = 2,
        
        [switch] $IncludeOriginal
    )
    #endregion Parameter
    begin {
        if ($Separator -eq 'Space') { $Separator = ' ' }
        Write-Verbose -Message "Starting $($MyInvocation.Mycommand)"
    }
    process {
        foreach ($Mac in $MacAddress) {
            $oldMac = $Mac
            $Mac = $Mac -replace '-', '' #Replace Dash
            $Mac = $Mac -replace ':', '' #Replace Colon
            $Mac = $Mac -replace ';', '' #Replace semicolon
            $Mac = $Mac -replace '/s', '' #Remove whitespace
            $Mac = $Mac -replace ' ', '' #Remove whitespace
            $Mac = $Mac -replace '\.', '' #Remove dots
            $Mac = $Mac.trim() #Remove space at the beginning
            $Mac = $Mac.trimend() #Remove space at the end
            switch ($Case) {
                'Upper' { $Mac = $mac.toupper() }
                'Uppercase' { $Mac = $mac.toupper() }
                'Lower' { $Mac = $mac.tolower() }
                'Lowercase' { $Mac = $mac.tolower() }
                'Ignore' { }
                Default { }
            }
            if ($Separator -ne 'None') {
                switch ($Split) {
                    2 { $Mac = $Mac -replace '(..(?!$))', "`$1$Separator" }
                    3 { $Mac = $Mac -replace '(...(?!$))', "`$1$Separator" }
                    4 { $Mac = $Mac -replace '(....(?!$))', "`$1$Separator" }
                    6 { $Mac = $Mac -replace '(......(?!$))', "`$1$Separator" }
                    default { $Mac = $Mac -replace '(..(?!$))', "`$1$Separator" }
                }
            }
            if (-not ($IncludeOriginal)) {
                write-output -InputObject $Mac
            } else {
                $prop = @{ OriginalMac = $oldMac ; FormattedMac = $mac }
                $obj = new-object -TypeName psobject -Property $prop
                write-output -InputObject $obj
            }
        }
    } #EndBlock Process
    end {
        Write-Verbose -Message "Ending $($MyInvocation.Mycommand)"
    }
}
#endregion Format-MacAddress

#region Convert-SecondsToHumanReadable
function Convert-SecondsToHumanReadable {
    <#
    .SYNOPSIS
    Converts a number of seconds to human readable time in English.

    .DESCRIPTION
    The function takes a number of seconds and converts it to a
    readable time format consisting of days, hours, minutes, and seconds.
    Output can be either a formatted text string or a PowerShell object.

    .PARAMETER Seconds
    Number of seconds to convert.

    .PARAMETER AsObject
    If specified, returns a PowerShell object with the fields:
    Days, Hours, Minutes, Seconds, and Text. If not specified, returns a formatted text string.
    .EXAMPLE
    Convert-SecondsToHumanReadable -Seconds 1322

    .EXAMPLE
    Convert-SecondsToHumanReadable -Seconds 1322 -AsObject

    .NOTES
    ComCompatible with PowerShell 7.
    #>
    param (
        [Parameter(Mandatory)]
        [int]$Seconds,

        [switch]$AsObject
    )

    $ts = [TimeSpan]::FromSeconds($Seconds)
    $parts = @()

    if ($ts.Days -gt 0) {
        $parts += if ($ts.Days -eq 1) { "1 day" } else { "$($ts.Days) days" }
    }

    if ($ts.Hours -gt 0) {
        $parts += if ($ts.Hours -eq 1) { "1 hour" } else { "$($ts.Hours) hours" }
    }

    if ($ts.Minutes -gt 0) {
        $parts += if ($ts.Minutes -eq 1) { "1 minute" } else { "$($ts.Minutes) minutes" }
    }

    if ($ts.Seconds -gt 0 -or $parts.Count -eq 0) {
        $parts += if ($ts.Seconds -eq 1) { "1 second" } else { "$($ts.Seconds) seconds" }
    }

    $text = $parts -join ' '

    if ($AsObject) {
        return [pscustomobject]@{
            Days    = $ts.Days
            Hours   = $ts.Hours
            Minutes = $ts.Minutes
            Seconds = $ts.Seconds
            Text    = $text
        }
    }

    return $text
}
#endregion Convert-SecondsToHumanReadable

#region Format-MacAddress
function Format-MacAddress {
    <#
    .SYNOPSIS
        Function to do a cleanup of a MACAddress string
    .DESCRIPTION
        Cleanup a MACAddress string and optionally format it with separators
    .PARAMETER MacAddress
        Specifies the MacAddress. Either a single string or an array of strings. Aliased to 'Address'
    .PARAMETER Separator
        Specifies the separator every X characters. Aliased to 'Delimiter'. Validated against set(':', 'None', '.', "-", ' ', 'Space', ';')
    .PARAMETER Case
        Specifies if the output is to be set in a particular case
        Upper Sets to upper case, 'a' becomes 'A'
        Uppercase Sets to upper case, 'a' becomes 'A'
        Lower Sets to lower case, 'A' becomes 'a'
        Lowercase Sets to lower case, 'A' becomes 'a'
        Ignore Does nothing to the case of the letters 'aB', so remains as 'aB'
    .PARAMETER Split
        Specifies how many characters to split the MacAddress on. Valid values are 2,3,4,6
    .EXAMPLE
        Format-MacAddress -MacAddress 1234567890ab
        12:34:56:78:90:ab
    .EXAMPLE
        Format-MacAddress -MacAddress '00:11:22:dD:ee:FF' -Case Upper
        00:11:22:DD:EE:FF
    .EXAMPLE
        Format-MacAddress -MacAddress '00:11:22:dD:ee:FF' -Case Lowercase
        001122ddeeff
    .EXAMPLE
        Format-MacAddress -MacAddress '00:11:22:dD:ee:FF' -Case Lowercase -Separator '-'
        00-11-22-dd-ee-ff
    .EXAMPLE
        Format-MacAddress -MacAddress '00:11:22:dD:ee:FF' -Case Lowercase -Separator '.'
        00.11.22.dd.ee.ff
    .EXAMPLE
        Format-MacAddress -Address '00:11:22:dD:ee:FF', '10005a123456' -case Uppercase -Delimiter '-'
        00-11-22-DD-EE-FF
        10-00-5A-12-34-56
        Showing how function can take an array of MacAddress using the alias 'Address' and the alias 'Delimiter' for the 'Separator' parameter
    .EXAMPLE
        '00:11:22:dD:ee:FF', '10005a123456' | Format-MacAddress -case Lowercase -Separator '.'
        00.11.22.dd.ee.ff
        10.00.5a.12.34.56
        Showing how the values for MacAddress can be received from the pipeline
    .EXAMPLE
        Format-MacAddress '10005a123456' -case Lowercase -Separator ':'
        10:00:5a:12:34:56
        Showing how MacAddress can be unnamed positional parameter
    .EXAMPLE
        '00:11:22:dD:ee:FF' | Format-MacAddress -Separator None -Case Ignore
        001122dDeeFF
    .EXAMPLE
        '00:11:22:dD:ee:FF', '10005a123456' | Format-MacAddress -case Lowercase -Separator '.' -Split 4
        0011.22dd.eeff
        1000.5a12.3456
    .EXAMPLE
        '00:11:22:dD:ee:FF', '10005a123456' | Format-MacAddress -case Lowercase -Separator '.' -Split 4 -IncludeOriginal
        OriginalMac FormattedMac
        ----------- ------------
        00:11:22:dD:ee:FF 0011.22dd.eeff
        10005a123456 1000.5a12.3456
    .OUTPUTS
        System.String
    .NOTES
        # Inspired and based on Clean-MacAddress.ps1 by Francois-Xavier www.lazywinadmin.com
        #
        # Daniel Ravnholt
        # Dark@rn.dk
        Modified:
        First RN release
    #>
    #region Parameter
    [OutputType('String')]
    [CmdletBinding()]
    param (
        [Parameter(Position=0, HelpMessage='Please enter a MAC address (12 hex)', Mandatory, ValueFromPipeline)]
        [Alias('Address')]
        [String[]] $MacAddress,
        
        [ValidateSet(':', 'None', '.', '-', ' ', 'Space', ';')]
        [Alias('Delimiter')]
        [string] $Separator = ':',
        
        [ValidateSet('Ignore', 'Upper', 'Uppercase', 'Lower', 'Lowercase')]
        [string] $Case = 'Lower',
        
        [ValidateSet(2,3,4,6)]
        [int] $Split = 2,
        
        [switch] $IncludeOriginal
    )
    #endregion Parameter
    begin {
        if ($Separator -eq 'Space') { $Separator = ' ' }
        Write-Verbose -Message "Starting $($MyInvocation.Mycommand)"
    }
    process {
        foreach ($Mac in $MacAddress) {
            $oldMac = $Mac
            $Mac = $Mac -replace '-', '' #Replace Dash
            $Mac = $Mac -replace ':', '' #Replace Colon
            $Mac = $Mac -replace ';', '' #Replace semicolon
            $Mac = $Mac -replace '/s', '' #Remove whitespace
            $Mac = $Mac -replace ' ', '' #Remove whitespace
            $Mac = $Mac -replace '\.', '' #Remove dots
            $Mac = $Mac.trim() #Remove space at the beginning
            $Mac = $Mac.trimend() #Remove space at the end
            switch ($Case) {
                'Upper' { $Mac = $mac.toupper() }
                'Uppercase' { $Mac = $mac.toupper() }
                'Lower' { $Mac = $mac.tolower() }
                'Lowercase' { $Mac = $mac.tolower() }
                'Ignore' { }
                Default { }
            }
            if ($Separator -ne 'None') {
                switch ($Split) {
                    2 { $Mac = $Mac -replace '(..(?!$))', "`$1$Separator" }
                    3 { $Mac = $Mac -replace '(...(?!$))', "`$1$Separator" }
                    4 { $Mac = $Mac -replace '(....(?!$))', "`$1$Separator" }
                    6 { $Mac = $Mac -replace '(......(?!$))', "`$1$Separator" }
                    default { $Mac = $Mac -replace '(..(?!$))', "`$1$Separator" }
                }
            }
            if (-not ($IncludeOriginal)) {
                write-output -InputObject $Mac
            } else {
                $prop = @{ OriginalMac = $oldMac ; FormattedMac = $mac }
                $obj = new-object -TypeName psobject -Property $prop
                write-output -InputObject $obj
            }
        }
    } #EndBlock Process
    end {
        Write-Verbose -Message "Ending $($MyInvocation.Mycommand)"
    }
}

#endregion Format-MacAddress

#region Get-ComputerAdGroups
function Get-ComputerAdGroups {
    <#
    .SYNOPSIS
        Retrieves Active Directory group memberships for the current computer.

    .DESCRIPTION
        Queries Active Directory for the current computer account and returns
        a sorted list of Active Directory groups the computer is a direct member of.

        Note:
        - The primary group (e.g. "Domain Computers") is NOT included, as it is
          not exposed via the memberOf attribute in Active Directory.

    .OUTPUTS
        System.String[]

    .EXAMPLE
        Get-ComputerAdGroups

        Returns a sorted list of Active Directory group names for the current computer.
    #>

    [CmdletBinding()]
    param ()

    $computerSam = "$($env:COMPUTERNAME)$"

    $searcher = [ADSISEARCHER]"(&(objectClass=computer)(sAMAccountName=$computerSam))"
    $result   = $searcher.FindOne()

    if (-not $result) {
        Write-Error "Computer '$($env:COMPUTERNAME)' was not found in Active Directory."
        return
    }

    if (-not $result.Properties.memberof) {
        return @()
    }

    $groups = $result.Properties.memberof |
        ForEach-Object {
            $_ -replace '^CN=([^,]+).+$', '$1'
        } |
        Sort-Object

    return $groups
}
#endregion Get-ComputerAdGroups

#region Get-ExecutableArchitecture
function Get-ExecutableArchitecture {
    <#
    .Synopsis
    Determines whether an executable file is 16-bit, 32-bit or 64-bit.
    .DESCRIPTION
    Attempts to read the MS-DOS and PE headers from an executable file to determine its type.
    The command returns one of four strings (assuming no errors are encountered while reading the
    file):
    "Unknown", "16-bit", "32-bit", or "64-bit"
    .PARAMETER Path
    Path to the file which is to be checked.
    .EXAMPLE
    Get-ExecutableType -Path C:\Windows\System32\[more.com](http://more.com/)
    .INPUTS
    None. This command does not accept pipeline input.
    .OUTPUTS
    String
    .LINK
    http://msdn.microsoft.com/en-us/magazine/cc301805.aspx
    #>

    [CmdletBinding()]
    param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]
    $Path
    )
    try
    {
    try
    {
    $stream = New-Object System.IO.FileStream(
    $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Path),
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
    )
    }
    catch
    {
    throw "Error opening file $Path for Read: $($_.Exception.Message)"
    }
    $exeType = 'Unknown'
    if ([System.IO.Path]::GetExtension($Path) -eq '.COM')
    {
    # 16-bit .COM files may not have an MS-DOS header. We'll assume that any .COM file with no header
    # is a 16-bit executable, even though it may technically be a non-executable file that has been
    # given a .COM extension for some reason.
    $exeType = '16-bit'
    }
    $bytes = New-Object byte[](4)
    if ($stream.Length -ge 64 -and
    $stream.Read($bytes, 0, 2) -eq 2 -and
    $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A)
    {
    $exeType = '16-bit'
    if ($stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) -eq 0x3C -and
    $stream.Read($bytes, 0, 4) -eq 4)
    {
    if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 4) }
    $peHeaderOffset = [System.BitConverter]::ToUInt32($bytes, 0)
    if ($stream.Length -ge $peHeaderOffset + 6 -and
    $stream.Seek($peHeaderOffset, [System.IO.SeekOrigin]::Begin) -eq $peHeaderOffset -and
    $stream.Read($bytes, 0, 4) -eq 4 -and
    $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0 -and $bytes[3] -eq 0)
    {
    $exeType = 'Unknown'
    if ($stream.Read($bytes, 0, 2) -eq 2)
    {
    if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 2) }
    $machineType = [System.BitConverter]::ToUInt16($bytes, 0)
    switch ($machineType)
    {
    0x014C { $exeType = '32-bit' }
    0x0200 { $exeType = '64-bit' }
    0x8664 { $exeType = '64-bit' }
    }
    }
    }
    }
    }
    return $exeType
    }
    catch
    {
    throw
    }
    finally
    {
    if ($null -ne $stream) { $stream.Dispose() }
    }
}
#endregion Get-ExecutableArchitecture

#region Get-FileViaExplorer
function Get-FileViaExplorer {
    <#
    .SYNOPSIS
        Opens a file browser dialog to allow user selection of files.
    .DESCRIPTION
        Displays a Windows Forms OpenFileDialog for interactive file selection. Supports single or multiple file selection with optional file type filtering.
    .PARAMETER Startdir
        Specifies the initial directory path for the file browser. Defaults to Desktop.
    .PARAMETER Filter
        Specifies file type filter (e.g., "Text files (*.txt)|*.txt|All files (*.*)|*.*"). If not specified, all file types are shown.
    .PARAMETER MultipleFiles
        If specified, allows selection of multiple files. By default, only single file selection is allowed.
    .OUTPUTS
        Returns the selected file path or paths as a string or array of strings.
    .EXAMPLE
        Get-FileViaExplorer
        Opens file browser starting at Desktop.
    .EXAMPLE
        Get-FileViaExplorer -Startdir "C:\Users\Documents" -Filter "Text files (*.txt)|*.txt"
        Opens file browser at Documents folder filtered to show only .txt files.
    .EXAMPLE
        Get-FileViaExplorer -Filter "Image files (*.png;*.jpg)|*.png;*.jpg|All files (*.*)|*.*"
        Opens file browser filtered to show image files and all files.
    .EXAMPLE
        $pfx_path = Get-FileViaExplorer -Startdir "c:\certs" -filter 'Certifikat (*.pfx)|*.pfx'
        Opens file browser at c:\certs filtered to show only .pfx files and stores the selected file path in $pfx_path.
    .EXAMPLE
        Get-FileViaExplorer -MultipleFiles
        Opens file browser allowing selection of multiple files.
    #>
    Param(
        [String]$Startdir = [Environment]::GetFolderPath('Desktop'),
        [String]$Filter = "",
        [switch]$MultipleFiles = $false
    )

    try {
        Add-Type -AssemblyName System.Windows.Forms # Add the necessary .NET assembly for Windows Forms

        # Create a new OpenFileDialog object
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
        $FileBrowser.InitialDirectory = $Startdir

        # Conditionally set the filter if provided
        if ($Filter.length -gt 0) {
            $FileBrowser.Filter = $Filter
        }

        # Set the Multiselect property based on the MultipleFiles parameter
        $FileBrowser.Multiselect = $MultipleFiles.IsPresent

        # Show the file dialog and store the user's action (Selected file/files/cancel)
        $null = $FileBrowser.ShowDialog()

        # Return the selected file(s) based on whether multiple file selection is enabled
        if ($FileBrowser.Multiselect) {
            return $FileBrowser.FileNames    
        } else {
            return $FileBrowser.FileName
        }
    } catch {
        Write-Error "An error occurred: $_"
    } finally {
        # Clear resources used by OpenFileDialog
        $FileBrowser.Dispose()
    }
}
#endregion Get-FileViaExplorer

#region Get-FolderSize
function Get-FolderSize {
    <#
    .SYNOPSIS
        Calculates the total size of a folder.
    .DESCRIPTION
        Calculates the size of a folder in megabytes. Supports recursive directory traversal, minimum size filtering, and handling of offline files.
    .PARAMETER folder
        Specifies the folder path to measure. Accepts pipeline input.
    .PARAMETER recurse
        If specified, includes all subdirectories in the size calculation.
    .PARAMETER minSizeMb
        Specifies the minimum size in MB to display. Folders smaller than this value are not shown.
    .PARAMETER includeOnlineFiles
        If specified, includes online-only files in the size calculation. By default, offline files are excluded.
    .OUTPUTS
        Returns a formatted string with folder path and size in MB.
    .EXAMPLE
        Get-FolderSize -folder "C:\Users\Documents"
        Returns the size of the Documents folder.
    .EXAMPLE
        Get-FolderSize -folder "C:\Users\Documents" -Recurse
        Returns the total size including all subfolders.
    .EXAMPLE
        Get-FolderSize -folder "C:\Users\Documents" -minSizeMb 100
        Returns the size only if it is at least 100 MB.
    .EXAMPLE
        "C:\Temp", "C:\Windows\Temp" | Get-FolderSize -Recurse
        Calculates size of multiple folders via pipeline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [string]$folder,

        [switch]$recurse = $false,  # Boolean Arg

        [Parameter(Position=1)]
        [double]$minSizeMb,  # Minimum size in MB to display

        [switch]$includeOnlineFiles  # Include online-only files in the size calculation
    )

    process {
        $items = Get-ChildItem $folder -Recurse:$recurse -File -ErrorAction SilentlyContinue
        
        if (-not $includeOnlineFiles) {
            $items = $items | Where-Object { -not ($_.Attributes -like '*Offline*') }
        }

        $sizeInMb = [math]::Ceiling(($items | Measure-Object -Property Length -Sum).Sum / 1MB)

        if ($sizeInMb -ge $minSizeMb) {
            "{0}: {1:N1} MB" -f $folder, $sizeInMb
        }
    }
}
#endregion Get-FolderSize

#region Get-GithubData
function Get-GithubData {
    <#
    .SYNOPSIS
    Retrieves release information from a GitHub repository and optionally downloads release assets.

    .DESCRIPTION
    The Get-GithubData function queries the GitHub REST API to retrieve release data
    for a specified GitHub repository. By default, it returns the latest release object.

    The function can optionally:
    - Return only the latest release version tag
    - Exclude preview, beta, alpha, or release-candidate versions
    - Download a selected release asset to a local path
    - Select a specific asset by index
    - Filter assets using a wildcard pattern

    The GitHub API is queried using:
    https://api.github.com/repos/<user>/<repo>/releases

    .PARAMETER User
    Specifies the GitHub username or organization name.

    .PARAMETER Repo
    Specifies the GitHub repository name.

    .PARAMETER Download
    If specified, downloads a release asset from the selected release.
    If not specified, no files are downloaded.

    .PARAMETER DownloadPath
    Specifies the directory where the selected release asset will be downloaded.
    This parameter is required when the Download switch is used.

    .PARAMETER LatestVersion
    If specified, the function returns only the latest release version tag
    (tag_name) as a string and does not return the full release object.

    .PARAMETER AssetChoice
    Specifies the zero-based index of the release asset to download.
    This is useful when multiple assets exist for a release.
    The default value is 0.

    .PARAMETER SkipPreview
    If specified, excludes prerelease versions and releases with tag names
    containing alpha, beta, preview, or rc.

    .PARAMETER AssetFilter
    Specifies a wildcard pattern used to filter release assets by name
    (for example: *.zip or *windows*x64*).
    If multiple assets match, AssetChoice determines which asset is selected.

    .EXAMPLE
    Get-GithubData -User powershell -Repo powershell

    Returns the latest release object for the PowerShell GitHub repository.

    .EXAMPLE
    Get-GithubData -User powershell -Repo powershell -LatestVersion

    Returns only the latest version tag for the PowerShell repository.

    .EXAMPLE
    Get-GithubData -User powershell -Repo powershell -SkipPreview

    Returns the latest stable (non-preview) release object.

    .EXAMPLE
    Get-GithubData -User powershell -Repo powershell `
        -Download `
        -DownloadPath "C:\Temp" `
        -AssetFilter "*win*x64*"

    Downloads the first Windows x64 asset from the latest release
    to the specified download path.

    .OUTPUTS
    System.Object
    Returns a GitHub release object when not using -LatestVersion or -Download.

    System.String
    Returns the version tag when using -LatestVersion.

    System.Boolean
    Returns $false if no suitable releases or assets are found.

    .NOTES
    Requires internet access and a reachable GitHub API endpoint.
    Unauthenticated requests are subject to GitHub API rate limits.

    #>
    param(
        [string]$User, # GitHub username
        [string]$Repo, # Repository name
        [switch]$Download = $false, # Optional download flag, defaults to false
        [string]$DownloadPath, # Download path for the release asset, required if $Download is $true
        [switch]$LatestVersion, # Switch to only return the latest version
        [int]$AssetChoice = 0, # Sometimes the first file listed might not be the one you want. Default to 0
        [switch]$SkipPreview, # New parameter to skip preview, beta, or similar releases
        [string]$AssetFilter # New parameter for filtering assets by a wildcard pattern
    )

    # GitHub API URL for releases
    $Uri = "https://api.github.com/repos/$User/$Repo/releases"

    # Fetch releases
    $Releases = Invoke-RestMethod -Uri $Uri

    # Check if there are any releases
    if ($Releases.Count -gt 0) {
        if ($SkipPreview) {
            # Filter out prerelease and tags likely indicating non-stable releases
            $FilteredReleases = $Releases | Where-Object {
                -not $_.prerelease -and
                $_.tag_name -notmatch 'alpha|beta|preview|rc'
            }
        } else {
            $FilteredReleases = $Releases
        }

        if ($FilteredReleases.Count -gt 0) {
            $LatestRelease = $FilteredReleases[0]
        } else {
            Write-Output "No suitable releases found for this repository."
            return $false
        }

        $Version = $LatestRelease.tag_name
        $ReleaseDate = $LatestRelease.published_at

        if ($LatestVersion) {
            return $Version
        } else {
            if ($Download -and $LatestRelease.assets.Count -gt 0) {
                # Filter assets if AssetFilter is specified
                if ($AssetFilter) {
                    $FilteredAssets = $LatestRelease.assets | Where-Object { $_.name -like $AssetFilter }
                    # Use the first matched asset or the asset specified by AssetChoice if no filter matches
                    $Asset = $FilteredAssets[$AssetChoice] | Select-Object -First 1
                } else {
                    $Asset = $LatestRelease.assets[$AssetChoice]
                }

                if ($Asset) {
                    $DownloadUrl = $Asset.browser_download_url

                    # Specify the filename for download
                    $FileName = [System.IO.Path]::Combine($DownloadPath, $Asset.name)
                    Invoke-WebRequest -Uri $DownloadUrl -OutFile $FileName
                    Write-Output "Downloaded '$($Asset.name)' to '$DownloadPath'"
                } else {
                    Write-Output "No assets match the specified filter."
                    return $false
                }
            }

            # Output the latest release data
            Write-Output "Latest Version: $Version"
            Write-Output "Release Date: $ReleaseDate"
        }
        # Only show release info when not downloading
				if (-not $download) {
					return $LatestRelease
				}
    } else {
        Write-Output "No releases found for this repository."
        return $false
    }
}
#endregion Get-GithubData

#region Get-IconLnkTarget
function Get-IconLnkTarget {
    <#
    .SYNOPSIS
        Retrieves the target path of a Windows shortcut file.
    .DESCRIPTION
        Extracts the target path or full information from a .lnk (shortcut) file. Uses COM object to read shortcut properties.
    .PARAMETER lnk
        Specifies the path to the .lnk shortcut file.
    .PARAMETER FullInfo
        If specified, returns all shortcut properties. If not specified, returns only the target path.
    .OUTPUTS
        Returns the target path as a string, or a COM object with full shortcut information if -FullInfo is used.
    .EXAMPLE
        Get-IconLnkTarget -lnk "C:\Users\Desktop\MyShortcut.lnk"
        Returns the target path of the shortcut.
    .EXAMPLE
        Get-IconLnkTarget -lnk "C:\Users\Desktop\Chrome.lnk" -FullInfo
        Returns all properties of the shortcut including target, arguments, working directory, etc.
    #>
    param (
        [Parameter(Mandatory=$True, Position=0)][string]$lnk,
        [Parameter(Mandatory=$false)][switch]$FullInfo
    )
    if (test-path $lnk) {
        if ((get-item $lnk).Extension -eq ".lnk") {
            $linkitem = get-item $lnk
            $WSShell = New-Object -ComObject Wscript.Shell
            $iconinfo = $WSShell.CreateShortcut($linkitem.FullName)
            if ($iconinfo.TargetPath) {
                if ($FullInfo -eq $true) {
                    return $iconinfo
                } else {
                    return $iconinfo.TargetPath
                }
            } else {
                write-warning "Targetpath not found in .lnk file"
            }
        } else {
            write-error "File extension not .lnk"
        }
    } else {
        write-error "Lnk file not found"
    }
}
#endregion Get-IconLnkTarget

#region Get-ImageInformation
function Get-ImageInformation {
    <#
    .SYNOPSIS
        Retrieves image information using Windows Image Acquisition (WIA) API.
    .DESCRIPTION
        Loads an image file using the Windows Image Acquisition COM object and returns image properties.
    .PARAMETER Filepath
        Specifies the path to the image file. Accepts pipeline input.
    .OUTPUTS
        Returns a WIA image object with properties like width, height, etc.
    .EXAMPLE
        Get-ImageInformation -Filepath "C:\Pictures\photo.jpg"
        Returns image object for the specified photo.
    .EXAMPLE
        "C:\Pictures\photo.jpg" | Get-ImageInformation
        Gets image information via pipeline.
    #>
    param(
        [Parameter(
            Mandatory=$True,
            Position=0,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        $Filepath
    )
    $image  = New-Object -ComObject Wia.ImageFile
    $image.loadfile($filepath)
    return $image
}
#endregion Get-ImageInformation

#region Get-ProcessOwner
function Get-ProcessOwner {
    <#
    .SYNOPSIS
        Retrieves the owner of one or more running processes by name.

    .DESCRIPTION
        Uses the Win32_Process CIM class to locate all running processes that match
        the specified process name and resolves the user account that owns each
        process. The function returns a custom object containing the process name
        and the associated owner.

    .PARAMETER ProcessName
        Specifies the name of the process to query (for example, "explorer.exe").

    .OUTPUTS
        Returns a custom object with ProcessName and Owner properties.

    .EXAMPLE
        Get-ProcessOwner -ProcessName "explorer.exe"
        Returns the owner of all running explorer.exe processes.

    .EXAMPLE
        Get-ProcessOwner -ProcessName "powershell.exe"
        Retrieves the user accounts running PowerShell processes.

    .NOTES
        Requires sufficient privileges to query process ownership information.
        Uses Get-CimInstance instead of deprecated WMI cmdlets.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(
            ParameterSetName = 'ByName',
            Position = 0,
            Mandatory
        )]
        [string]$ProcessName,

        [Parameter(
            ParameterSetName = 'ByProcess',
            ValueFromPipeline,
            Mandatory
        )]
        [System.Diagnostics.Process]$Process
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByProcess') {
            $ProcessId   = $Process.Id
            $ProcessName = $Process.Name
        }
        else {
            Get-Process -Name $ProcessName -ErrorAction Stop |
                ForEach-Object {
                    $ProcessId   = $_.Id
                    $ProcessName = $_.Name
                }
        }

        $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId"
        $owner   = Invoke-CimMethod -InputObject $cimProc -MethodName GetOwner

        [PSCustomObject]@{
            ProcessName = $ProcessName
            ProcessId   = $ProcessId
            Owner       = if ($owner.ReturnValue -eq 0) {
                              $owner.User
                          } else {
                              '<ukendt>'
                          }
        }
    }
}
#endregion Get-ProcessOwner

#region Set-ScheduledTaskMSA
function Set-ScheduledTaskMSA {
    <#
    .SYNOPSIS
        Configures a scheduled task to run under a Managed Service Account (MSA).
    .DESCRIPTION
        Updates an existing scheduled task's principal to use a Managed Service Account for execution. Supports setting privilege level to limited or highest.
    .PARAMETER TaskName
        Specifies the name of the scheduled task to update.
    .PARAMETER TaskPath
        Specifies the path of the task. Defaults to root (\\).
    .PARAMETER MSAName
        Specifies the MSA name. Must end with $ (e.g., 'MyMSA$').
    .PARAMETER RunWithHighestPrivileges
        If specified, sets the task to run with highest privileges. By default, runs with limited privileges.
    .EXAMPLE
        Set-ScheduledTaskMSA -TaskName "MyBackupTask" -MSAName "BackupMSA$"
        Configures MyBackupTask to run under BackupMSA.
    .EXAMPLE
        Set-ScheduledTaskMSA -TaskName "AdminTask" -TaskPath "\\Custom\\Path" -MSAName "AdminMSA$" -RunWithHighestPrivileges
        Configures task with highest privilege level.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$TaskName,

        [Parameter(Mandatory = $true)]
        [string]$TaskPath = "\\",

        [Parameter(Mandatory = $true)]
        [string]$MSAName,

        [Parameter(Mandatory = $false)]
        [switch]$RunWithHighestPrivileges = $false
    )

    # Valider, at MSA'en er korrekt formatteret
    if ($MSAName -notlike "*`$") {
        throw "MSA-name must end with a `$ (e.g., 'MyMSA$')."
    }

    if ($TaskPath[0] -ne "\") { $TaskPath = "\$($TaskPath)" } # Append leading \ if not set

    # Find den fulde sti til opgaven
    $FullTaskPath = Join-Path -Path $TaskPath -ChildPath $TaskName

    try {
        # Hent den eksisterende opgave
        $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName

        if (-not $task) {
            throw "The specified task '$FullTaskPath' was not found."
        }

        # Update principal
        $principal = New-ScheduledTaskPrincipal -UserId $MSAName -LogonType Password
        if ($RunWithHighestPrivileges) {
            $principal.RunLevel = "Highest"
        } else {
            $principal.RunLevel = "Limited"
        }

        # Opdater opgaven
        Set-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Principal $principal

        Write-Host "The task '$FullTaskPath' was successfully updated to MSA: $MSAName" -ForegroundColor Green

        if ($RunWithHighestPrivileges) {
            Write-Host "The task is set to run with highest privileges." -ForegroundColor Green
        } else {
            Write-Host "The task is set to run with standard privileges." -ForegroundColor Green
        }

    } catch {
        Write-Error "An error occurred: $_"
    }
}
#endregion Set-ScheduledTaskMSA

#region Get-Software
function Get-Software {
    <#
    .SYNOPSIS
        Retrieves installed software from the Windows registry.
    .DESCRIPTION
        Lists installed applications by querying the Windows registry uninstall locations. Supports filtering by display name, version, installation date, and uninstall path.
    .PARAMETER DisplayName
        Specifies a display name filter pattern. Defaults to all (*)
    .PARAMETER Version
        Specifies a version filter pattern. Defaults to all (*)
    .PARAMETER InstallationDate
        Specifies an installation date filter pattern. Defaults to all (*)
    .PARAMETER UninstallationPath
        Specifies an uninstall path filter pattern. Defaults to all (*)
    .OUTPUTS
        Returns objects with DisplayName, DisplayVersion, InstallDate, Size, UninstallString, and registry path properties.
    .EXAMPLE
        Get-Software -DisplayName "Chrome"
        Returns all installed Chrome versions.
    .EXAMPLE
        Get-Software -DisplayName "*.Net*"
        Lists all .NET Framework installations.
    #>
    param (
        [Parameter(Position=0, Mandatory = $false, HelpMessage="DisplayName", ValueFromPipeline = $true)]
        $DisplayName='*',
        [Parameter(Mandatory = $false, HelpMessage="Version", ValueFromPipeline = $true)]
        $Version='*',
        [Parameter(Mandatory = $false, HelpMessage="Installation date", ValueFromPipeline = $true)]
        $InstallationDate='*',
        [Parameter(Mandatory = $false, HelpMessage="How to uninstall", ValueFromPipeline = $true)]
        $UninstallationPath='*'
    )
    
    $UninstallationPaths = @(
        "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "Registry::HKEY_CURRENT_USER\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $ResultArray = Get-ItemProperty -Path $UninstallationPaths | ForEach-Object {
        # Omdan PSPath til de ønskede formater
        $regPath = ($_.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '')
        $psRegPath = $regPath -replace '^HKEY_LOCAL_MACHINE', 'HKLM:' -replace '^HKEY_CURRENT_USER', 'HKCU:'

        [PSCustomObject]@{
            DisplayName    = $_.DisplayName
            DisplayVersion = $_.DisplayVersion
            InstallDate    = $_.InstallDate
            'Size in MB'   = [Math]::Round($_.EstimatedSize / 1MB)
            UninstallString= $_.UninstallString
            RegPath        = $regPath
            PsRegPath      = $psRegPath
        }
    }

    $FilteredResults = $ResultArray | Where-Object {
        $_.DisplayName -and 
        $_.DisplayName -like $DisplayName -and 
        $_.DisplayVersion -like $Version -and 
        $_.UninstallString -like $UninstallationPath -and 
        $_.InstallDate -like $InstallationDate
    }

    return $FilteredResults
}
#endregion Get-Software

#region Get-RegistryUninstallKey
function Get-RegistryUninstallKey {
    <#
    .SYNOPSIS
        Searches for uninstall registry keys matching a search pattern.
    .DESCRIPTION
        Queries both 32-bit and 64-bit registry uninstall locations and returns matching software entries with GUID, name, version, and installation date.
    .PARAMETER SearchFor
        Specifies a regex pattern to match against display names.
    .OUTPUTS
        Returns custom objects with GUID, DisplayName, DisplayVersion, UninstallString, InstallDate, FullPath, and isWow6432Node properties.
    .EXAMPLE
        Get-RegistryUninstallKey -SearchFor "Python"
        Returns all Python installations found in registry.
    .EXAMPLE
        Get-RegistryUninstallKey -SearchFor "Microsoft.*"
        Lists all Microsoft products in uninstall registry.
    #>
param(
    [Parameter(Mandatory=$true)]
    $SearchFor
)
$results = @() # Array til at gemme resultater
$registryPaths = @(
    @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; isWow6432Node=$false},
    @{Path='HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; isWow6432Node=$true}
)

foreach ($reg in $registryPaths) {
    $keys = Get-ChildItem $reg.Path -ErrorAction SilentlyContinue
    
    $keys | ForEach-Object {
        $obj = New-Object psobject
        Add-Member -InputObject $obj -MemberType NoteProperty -Name GUID -Value $_.PSChildName
        Add-Member -InputObject $obj -MemberType NoteProperty -Name DisplayName -Value $_.GetValue("DisplayName")
        Add-Member -InputObject $obj -MemberType NoteProperty -Name DisplayVersion -Value $_.GetValue("DisplayVersion")
        Add-Member -InputObject $obj -MemberType NoteProperty -Name UninstallString -Value $_.GetValue("UninstallString")
        
        $installDate = $_.GetValue("InstallDate")
        if ($installDate -match '^(\d{4})(\d{2})(\d{2})$') {
            $installDate = [datetime]::ParseExact($installDate, 'yyyyMMdd', $null)
        } else {
            $installDate = $null
        }
        Add-Member -InputObject $obj -MemberType NoteProperty -Name InstallDate -Value $installDate
        
        Add-Member -InputObject $obj -MemberType NoteProperty -Name FullPath -Value "registry::$_"
        Add-Member -InputObject $obj -MemberType NoteProperty -Name isWow6432Node -Value ([switch]$reg.isWow6432Node)
        
        $obj.FullPath = $obj.FullPath -replace "\[", "``[" -replace "\]", "``]"
        
        $results += $obj
    }
}

$results | Sort-Object DisplayName | Where-Object { $_.DisplayName -match $SearchFor }
}
#endregion Get-RegistryUninstallKey

#region Get-UserAdGroups
function Get-UserAdGroups {
    <#
    .SYNOPSIS
        Retrieves Active Directory group memberships for the current user.

    .DESCRIPTION
        Queries Active Directory for the currently logged-on user and returns
        a sorted list of AD group names the user is a member of.

        The function uses ADSI to perform a lightweight LDAP search and extracts
        the Common Name (CN) of each group.

    .OUTPUTS
        System.String[]

    .EXAMPLE
        Get-UserAdGroups

        Returns a sorted list of Active Directory group names for the current user.
    #>

    [CmdletBinding()]
    param ()

    $searcher = [ADSISEARCHER]"(samAccountName=$($env:USERNAME))"
    $result   = $searcher.FindOne()

    if (-not $result) {
        Write-Error "User '$($env:USERNAME)' was not found in Active Directory."
        return
    }

    $groups = $result.Properties.memberof |
        ForEach-Object {
            $_ -replace '^CN=([^,]+).+$', '$1'
        } |
        Sort-Object

    return $groups
}
#endregion Get-UserAdGroups

#region Get-Wanip
Function Get-WanIp () {
    <#
    .SYNOPSIS
        Retrieves your public WAN IP address and related information.
    .DESCRIPTION
        Queries an external API to get your public IP address along with location, ISP, hostname, and other information. Optionally copies the IP to clipboard.
    .PARAMETER CopyIpToClipboard
        If specified, copies the IP address to the clipboard.
    .OUTPUTS
        Returns formatted IP information including address, location, ISP, and hostname.
    .EXAMPLE
        Get-Wanip
        Displays WAN IP and related information.
    .EXAMPLE
        Get-Wanip -CopyIpToClipboard
        Gets WAN IP and copies it to clipboard.
    #>
    param (
        [switch]$CopyIpToClipboard = $false  #Boolean Arg
    )
    $ProgressPreference = 'SilentlyContinue'
	$wanip = (Invoke-WebRequest "https://wtfismyip.com/json").content
    $ProgressPreference = 'Continue'

	if (!($wanip)) { Write-Host "Could not find Wanip via wtfismyip.com" -ForegroundColor Yellow; break }

	$wanip = $wanip.Replace("YourFucking","")
	$wanip = $wanip | convertfrom-json
	($wanip | out-string).trim()
    if ($CopyIpToClipboard -eq $true) {
        Set-Clipboard -Value $($wanip.IPAddresse)
    }
}
#endregion Get-Wanip

#region Import-TaskXml
function Import-TaskXml {
    <#
    .SYNOPSIS
        Imports a scheduled task from an XML definition file.
    .DESCRIPTION
        Registers a scheduled task using an XML task definition file. Automatically ensures compatibility for Managed Service Accounts.
    .PARAMETER TaskXmlPath
        Specifies the path to the XML task definition file.
    .PARAMETER TaskName
        Specifies the name to assign to the imported task.
    .EXAMPLE
        Import-TaskXml -TaskXmlPath "C:\Tasks\BackupTask.xml" -TaskName "BackupTask"
        Imports the task from XML file.
    .EXAMPLE
        Import-TaskXml -TaskXmlPath "C:\Exports\task.xml" -TaskName "MyScheduledTask"
        Registers task with MSA compatibility.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$TaskXmlPath,

        [Parameter(Mandatory = $true)]
        [string]$TaskName
    )

    try {
        $taskService = New-Object -ComObject "Schedule.Service"
        $taskService.Connect()

        $taskFolder = $taskService.GetFolder("\")

        # Read XML content
        $taskXml = Get-Content -Path $TaskXmlPath -Raw

        # Register the task from XML
        $taskDefinition = $taskService.NewTask(0)
        $taskDefinition.XmlText = $taskXml

        # Ensure compatibility for Managed Service Accounts
        if ($taskDefinition.Settings.Compatibility -lt 2) {
            $taskDefinition.Settings.Compatibility = 2 # TASK_COMPATIBILITY_V2
        }

        $taskFolder.RegisterTaskDefinition(
            $TaskName,
            $taskDefinition,
            6, # TASK_CREATE_OR_UPDATE
            $null, # UserId (optional)
            $null, # Password (optional)
            3 # TASK_LOGON_SERVICE_ACCOUNT
        )

        Write-Host "Task '$TaskName' imported successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to import task: $_"
    }
}
#endregion Import-TaskXml

#region Install-Chocolatey
function Install-Chocolatey {
    <#
    .SYNOPSIS
        Installs or detects Chocolatey package manager.
    .DESCRIPTION
        Checks if Chocolatey is installed. If not, downloads and installs it from the official source with automatic execution policy and TLS configuration.
    .OUTPUTS
        Returns $true if already installed, $false if newly installed.
    .EXAMPLE
        Install-Chocolatey
        Installs Chocolatey if not present.
    #>
    # Check if Chocolatey is installed
    $choco_installed = Get-Command choco -ErrorAction SilentlyContinue
    if ($choco_installed) {
        Write-Output "Chocolatey is already installed."
        return $true
    } else {
        Write-Output "Chocolatey is not installed."
        Write-Output"Press a key to install Chocolatey from https://community.chocolatey.org/install.ps1"
        pause
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        return $false
    }
}
#endregion Install-Chocolatey

#region Install-Notion
function Install-Notion {
    <#
    .SYNOPSIS
        Installs or detects Notion application using Winget.
    .DESCRIPTION
        Checks if Notion is installed via Winget. If not found, downloads and installs it automatically. Closes any running Notion instances before installation.
    .OUTPUTS
        Displays installation status messages.
    .EXAMPLE
        Install-Notion
        Installs Notion if not already present.
    #>
    # Check if Winget is installed
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Error "Winget is not installed. Please install Winget to proceed."
        return
    }
    # Check if Notion is already installed
    $notion_installed = winget list --name "Notion" | Select-String "Notion"
    if ($notion_installed) {
        Write-Output "Notion is already installed."
    } else {
        # Install Notion using Winget
        if (Get-Process -Name "Notion" -ErrorAction SilentlyContinue) {
            Write-Output "Notion is currently running. Closing Notion."
            Stop-Process -Name "Notion" -Force
        }
        Write-Output "Installing Notion..."
        winget install --id=Notion.Notion -e --source=winget --override "/S /D=""C:\Program Files\Notion"""
        Write-Output "Notion installation completed."
    }
}
#endregion Install-Notion

#region Invoke-CleanupHistory
function Invoke-CleanupHistory {
    <#
    .SYNOPSIS
        Cleans Windows Recent files and clipboard history.
    .DESCRIPTION
        Removes all recent file history from Recent, AutomaticDestinations, and CustomDestinations folders. Clears the clipboard and displays a countdown before clearing the screen.
    .EXAMPLE
        Invoke-CleanupHistory
        Cleans all history and clipboard.
    #>
    $recent_userpath = "$env:APPDATA\microsoft\windows\recent"
    $number_of_files = (Get-ChildItem $recent_userpath -Recurse -file).count
    "Found: $($number_of_files) files to clean"
    if ($number_of_files -gt 0) {
        remove-item "$recent_userpath\*.*"
        "Cleanup Recent done"
        remove-item "$recent_userpath\AutomaticDestinations\*.*" -Recurse
        "Cleanup AutomaticDestinations done"
        remove-item "$recent_userpath\CustomDestinations\*.*" -Recurse
        "Cleanup CustomDestinations done"
    } else {
        "No files to cleanup"
    }
    Set-Clipboard -Value ""
    "Clipboard cleared"
    $count = 3
    while ($count -gt 0) {
        "Clean screen in $($count)"
        $count--
        Start-Sleep -seconds 1
    }
    Clear-Host    
}
#endregion Invoke-CleanupHistory

#region Invoke-PauseWithTimeout
function Invoke-PauseWithTimeout {
    <#
    .SYNOPSIS
        Pauses script execution with a timeout and keystroke detection.
    .DESCRIPTION
        Displays a message and waits for user input or timeout. Allows pressing a key to resume immediately or wait for timeout period to expire.
    .PARAMETER message
        Specifies the message to display.
    .PARAMETER SleepSeconds
        Specifies the timeout duration in seconds.
    .EXAMPLE
        Invoke-PauseWithTimeout -message "Press a key to continue..." -SleepSeconds 10
        Waits 10 seconds or until key is pressed.
    #>
    param (
    [Parameter(Mandatory=$True, Position=0)][string]$message,
    [Parameter(Mandatory=$True)][int]$SleepSeconds
    )

    $sleepSeconds = 10
    $timeout = New-TimeSpan -Seconds $sleepSeconds
    $stopWatch = [Diagnostics.Stopwatch]::StartNew()

    write-host $message

    while ($stopWatch.Elapsed -lt $timeout)
    {
        if ($Host.UI.RawUI.KeyAvailable)
        {
            $keyPressed = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyUp, IncludeKeyDown")
            if ($keyPressed.KeyDown -eq "True") { break }
        }
    }
}
#endregion Invoke-PauseWithTimeout

#region Search-FileContent
function Search-FileContent {
    <#
    .SYNOPSIS
        Searches for specific content within files in a given path.
    .DESCRIPTION
        Searches for files containing specified content.
        Displays matching lines with line numbers.
        Displays one-line error messages per file if a file cannot be read.
    .PARAMETER Content
        Text to search for.
    .PARAMETER Filter
        File filter (e.g. *.log).
    .PARAMETER Recurse
        Search recursively.
    .PARAMETER Path
        Root path. Defaults to current location.
    .PARAMETER HideContent
        Only display file paths when content is found.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [string]$Content,

        [string]$Filter,

        [switch]$Recurse,

        [string]$Path = (Get-Location),

        [switch]$HideContent
    )

    $gciParams = @{
        Path        = $Path
        File        = $true
        ErrorAction = 'SilentlyContinue'
    }

    if ($Filter)   { $gciParams.Filter  = $Filter }
    if ($Recurse)  { $gciParams.Recurse = $true }

    $files = Get-ChildItem @gciParams

    foreach ($file in $files) {
        try {
            $matches = Select-String -Path $file.FullName -Pattern $Content -SimpleMatch -ErrorAction Stop

            if ($matches) {
                if ($HideContent) {
                    Write-Host $file.FullName -ForegroundColor Green
                }
                else {
                    Write-Host "In: $($file.FullName)" -ForegroundColor Cyan
                    foreach ($match in $matches) {
                        Write-Host ("  Line {0}: {1}" -f $match.LineNumber, $match.Line)
                    }
                }
            }
        }
        catch [System.UnauthorizedAccessException] {
            Write-Warning "Access denied: Unable to read file '$($file.FullName)'."
        }
        catch [System.IO.IOException] {
            Write-Warning "File is locked: Unable to read file '$($file.FullName)'."
        }
        catch {
            Write-Warning "Unable to read file '$($file.FullName)'."
        }
    }
}
#endregion Search-FileContent

#region Show-Calendar
function Show-Calendar {
    <#
    .SYNOPSIS
    Displays a visual representation of a calendar.

    .DESCRIPTION
    Displays a visual representation of a calendar. The function supports multiple months
    and allows highlighting of specific dates or date ranges.

    .PARAMETER Start
    The first month to display.

    .PARAMETER End
    The last month to display.

    .PARAMETER FirstDayOfWeek
    Specifies which day the week starts on.

    .PARAMETER HighlightDay
    Specific day numbers to highlight (for example, 1..10 or 25..31).

    .PARAMETER HighlightDate
    Specific dates to highlight. Must be provided as DateTime objects.

    .EXAMPLE
    Show-Calendar

    .EXAMPLE
    Show-Calendar -Start (Get-Date '2025-03-01') -End (Get-Date '2025-05-01')

    .EXAMPLE
    Show-Calendar -HighlightDay (1..10) -HighlightDate (Get-Date '2025-12-25')
    #>
    <#
    .SYNOPSIS
    Displays a visual representation of a calendar.

    .DESCRIPTION
    Displays a visual representation of a calendar. The function supports multiple months
    and allows highlighting of specific dates or date ranges.

    .PARAMETER Start
    The first month to display.

    .PARAMETER End
    The last month to display.

    .PARAMETER FirstDayOfWeek
    Specifies which day the week starts on.

    .PARAMETER HighlightDay
    Specific day numbers to highlight (for example, 1..10 or 25..31).

    .PARAMETER HighlightDate
    Specific dates to highlight. Must be provided as DateTime objects.

    .EXAMPLE
    Show-Calendar

    .EXAMPLE
    Show-Calendar -Start (Get-Date '2025-03-01') -End (Get-Date '2025-05-01')

    .EXAMPLE
    Show-Calendar -HighlightDay (1..10) -HighlightDate (Get-Date '2025-12-25')
    #>
    param(
        [DateTime] $Start = [DateTime]::Today,
        [DateTime] $End   = $Start,
        [System.DayOfWeek] $FirstDayOfWeek,
        [int[]] $HighlightDay,
        [DateTime[]] $HighlightDate = @([DateTime]::Today.Date)
    )

    # Normalize start and end to first day of month
    $Start = [DateTime]::new($Start.Year, $Start.Month, 1)
    $End   = [DateTime]::new($End.Year,   $End.Month,   1)

    $dateTimeFormat = (Get-Culture).DateTimeFormat
    if ($PSBoundParameters.ContainsKey('FirstDayOfWeek')) {
        $dateTimeFormat.FirstDayOfWeek = $FirstDayOfWeek
    }

    while ($Start -le $End) {

        $currentDay = $Start

        while ($currentDay.DayOfWeek -ne $dateTimeFormat.FirstDayOfWeek) {
            $currentDay = $currentDay.AddDays(-1)
        }

        $weeks     = @()
        $dayNames  = @()
        $currentWeek = [pscustomobject]@{}

        while (
            ($currentDay -lt $Start.AddMonths(1)) -or
            ($currentDay.DayOfWeek -ne $dateTimeFormat.FirstDayOfWeek)
        ) {
            $dayName = '{0:ddd}' -f $currentDay
            if ($dayNames -notcontains $dayName) {
                $dayNames += $dayName
            }

            $displayDay = ' {0,2} ' -f $currentDay.Day

            if ($HighlightDate -contains $currentDay.Date) {
                $displayDay = '*{0,2}*' -f $currentDay.Day
            }
            elseif ($HighlightDay -and $HighlightDay[0] -eq $currentDay.Day) {
                $displayDay = '[{0,2}]' -f $currentDay.Day
                $null, $HighlightDay = $HighlightDay
            }

            $currentWeek | Add-Member -NotePropertyName $dayName -NotePropertyValue $displayDay

            $currentDay = $currentDay.AddDays(1)

            if ($currentDay.DayOfWeek -eq $dateTimeFormat.FirstDayOfWeek) {
                $weeks += $currentWeek
                $currentWeek = [pscustomobject]@{}
            }
        }

        $calendar = $weeks | Format-Table $dayNames -AutoSize | Out-String

        $width   = ($calendar -split "`n" | Measure-Object Length -Maximum).Maximum
        $header  = '{0:MMMM yyyy}' -f $Start
        $padding = ' ' * [Math]::Max(0, ($width - $header.Length) / 2)

        ("`n{0}{1}`n{2}" -f $padding, $header, $calendar).TrimEnd()

        $Start = $Start.AddMonths(1)
    }
}
#endregion Show-Calendar

#region Test-NetConnectionContinuous
function Test-NetConnectionContinuous {
    <#
    .SYNOPSIS
        Continuously pings a URL and displays real-time statistics.
    .DESCRIPTION
        Performs repeated ping tests against a target URL and displays live statistics including current, minimum, maximum, and average latency, packet loss, and uptime. Optionally copies the resolved IP to clipboard.
    .PARAMETER Url
        Specifies the target URL or hostname to ping.
    .PARAMETER Interval
        Specifies the interval between pings in milliseconds. Defaults to 1000 (1 second).
    .PARAMETER CopyIpToClipboard
        If specified, copies the resolved IP address to the clipboard.
    .OUTPUTS
        Displays live ping statistics in the console. Press Ctrl+C to stop.
    .EXAMPLE
        Test-NetConnectionContinuous -Url "google.com"
        Continuously pings Google and displays statistics.
    .EXAMPLE
        Test-NetConnectionContinuous -Url "8.8.8.8" -Interval 500 -CopyIpToClipboard
        Pings every 500ms and copies IP to clipboard.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter()]
        [int]$Interval = 1000, # Interval in milliseconds between pings

        [Parameter(Mandatory = $false)]
        [switch]$CopyIpToClipboard = $false # Copies IP address to clipboard
    )

    #region functions
    function Compare-DateTime {
    param(
      [Parameter(Mandatory = $true)]
      [datetime]$DateTime1,
  
      [Parameter(Mandatory = $true)]
      [datetime]$DateTime2
    )
  
    $TimeDifference = New-TimeSpan -Start $DateTime1 -End $DateTime2
  
    $Days = $TimeDifference.Days
    $Hours = $TimeDifference.Hours
    $Minutes = $TimeDifference.Minutes
    $Seconds = $TimeDifference.Seconds
  
    $Resultat = ""
  
    if ($Days -gt 0) {
      $Resultat += "$Days day"
      if ($Days -gt 1) {
        $Resultat += "s"
      }
    }
  
    if ($Hours -gt 0) {
      if ($Resultat -ne "") {
        $Resultat += ", "
      }
      $Resultat += "$Hours hour"
      if ($Hours -gt 1) {
        $Resultat += "s"
      }
    }
  
    if ($Minutes -gt 0) {
      if ($Resultat -ne "") {
        $Resultat += ", "
      }
      $Resultat += "$Minutes minute"
      if ($Minutes -gt 1) {
        $Resultat += "s"
      }
    }
  
    if ($Seconds -gt 0) {
      if ($Resultat -ne "") {
        $Resultat += " and "
      }
      $Resultat += "$Seconds second"
      if ($Seconds -gt 1) {
        $Resultat += "s"
      }
    }
  
    return $Resultat
    }
    #endregion
  
    # Initialization of variables
    $minPing = $null
    $maxPing = $null
    $sumPing = 0
    $packetsSent = 0
    $packetsLost = 0
    $StartTime = Get-Date

    while ($true) {
        # Ping webaddress
        $pingResult = Test-Connection -TargetName $Url -Count 1 -ErrorAction SilentlyContinue

        # Clear console
        Clear-Host

        if ($CopyIpToClipboard) {
        # Copy IP address to clipboard
            if ($null -ne $pingResult.Address) {
                if ($packetsSent -eq 0) {
                    $pingResult.Address | Set-Clipboard
                }
                if ($packetsSent -lt 3) {
                Write-Host "IP-address copied to clipboard" -foregroundcolor yellow
                }
            }
        }
        $packetsSent++

        # Update statistics
        if ($pingResult.Status -eq "Success") {
            $pingTime = $pingResult.Latency
            $sumPing += $pingTime
            if ($null -eq $minPing -or $pingTime -lt $minPing) {
                $minPing = $pingTime
            }
            if ($null -eq $maxPing -or $pingTime -gt $maxPing) {
                $maxPing = $pingTime
            }
        } else {
            $packetsLost++
        }

        # Calculate average ping time without [Math]::Round() and with 2 decimal places
        if ($packetsSent - $packetsLost -gt 0) {
            $avgPing = $sumPing / ($packetsSent - $packetsLost)
            $avgPing = "{0:N2}" -f $avgPing # Format to 2 decimal places
        } else {
            $avgPing = 0 # Avoid division by zero
        }


        Write-Host "Ping statistics for $($Url):" -ForegroundColor Green
        Write-Host "Recipient IP: $($pingResult.Address)" -ForegroundColor Gray
        if ($pingResult.Status -eq "Success") {
        Write-Host "Pinging - $($pingResult.Latency)ms" -ForegroundColor Green
        } elseif ($pingResult.Status -eq "TimedOut") {
        Write-Host "No connection" -ForegroundColor Red
        } else {
        Write-Host "Error - $($PingResult.Status)" -ForegroundColor Red
        }
        write-host "Started: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor DarkGray
        #Write-Host "Time since start: $([int]((Get-Date) - $StartTime).TotalSeconds) seconds"
        Write-Host "Time since start: $(Compare-DateTime -DateTime1 $StartTime -DateTime2 (Get-Date))"
        ""
        Write-Host "Current ping: $($pingResult.Latency) ms"
        Write-Host "Highest ping: $maxPing ms"
        Write-Host "Lowest ping: $minPing ms"
        Write-Host "Average ping: $($avgPing) ms"
        Write-Host "Packets sent: $packetsSent"
        Write-Host "Packets lost: $packetsLost"

        # Wait before next ping
        Start-Sleep -Milliseconds $Interval
    }
}

function Test-Numeric ($Value) {
    <#
    .SYNOPSIS
        Tests if a value is numeric.
    .DESCRIPTION
        Checks if the provided value matches a numeric pattern including decimals.
    .PARAMETER Value
        Specifies the value to test.
    .OUTPUTS
        Returns $true if numeric, $false otherwise.
    .EXAMPLE
        Test-Numeric "123.45"
        Returns: True
    .EXAMPLE
        Test-Numeric "abc"
        Returns: False
    #>
    return $Value -match "^[\d\.]+$"
}
#endregion Test-Numeric

#region Test-PendingReboot
function Test-PendingReboot {
    <#
    .SYNOPSIS
    Checks whether a Windows system requires a reboot.

    .DESCRIPTION
    Evaluates common reboot indicators such as:
    - Component Based Servicing
    - Windows Update
    - Pending file rename operations
    - SCCM client reboot status (via CIM)

    The function returns a concise and human-readable result.

    .OUTPUTS
    PSCustomObject

    .EXAMPLE
    Test-PendingReboot
    #>
    [CmdletBinding()]
    param ()

    $reasons = [System.Collections.Generic.List[string]]::new()

    # Component Based Servicing
    if (Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons.Add('Component Based Servicing')
    }

    # Windows Update
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentControlSet\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons.Add('Windows Update')
    }

    # Pending file rename operations (excluding Windows\Temp)
    try {
        $pendingRenames = (Get-ItemProperty `
            -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
            -Name 'PendingFileRenameOperations' `
            -ErrorAction Stop
        ).PendingFileRenameOperations

        if ($pendingRenames | Where-Object { $_ -and $_ -notmatch '\\Windows\\Temp\\' }) {
            $reasons.Add('Pending file rename operations')
        }
    }
    catch {
        # Ignore missing value
    }

    # SCCM / ConfigMgr (CIM)
    try {
        $cimResult = Invoke-CimMethod `
            -Namespace 'root\ccm\clientsdk' `
            -ClassName 'CCM_ClientUtilities' `
            -MethodName 'DetermineIfRebootPending' `
            -ErrorAction Stop

        if ($cimResult.RebootPending) {
            $reasons.Add('SCCM client')
        }
    }
    catch {
        # SCCM not present
    }

    [PSCustomObject]@{
        RebootRequired = ($reasons.Count -gt 0)
        Reasons        = $reasons -join ', '
    }
}
#endregion Test-PendingReboot

#region Test-SoftwareSources
function Test-SoftwareSources {
    <#
    .SYNOPSIS
        Checks for invalid software source paths in registry.
    .DESCRIPTION
        Scans Windows Installer registry for software products with missing or invalid source paths. Optionally removes invalid source entries.
    .PARAMETER DeleteInvalidSources
        If specified, removes invalid source entries from registry.
    .OUTPUTS
        Displays summary of total products, products with sources, and invalid products.
    .EXAMPLE
        Test-SoftwareSources
        Reports invalid sources without deleting.
    .EXAMPLE
        Test-SoftwareSources -DeleteInvalidSources
        Removes invalid source entries.
    #>
    param(
        [switch]$DeleteInvalidSources
    )

    $regPath = "HKLM:\SOFTWARE\Classes\Installer\Products"

    $totalProducts   = 0
    $checkedProducts = 0
    $invalidProducts = 0

    foreach ($productKey in Get-ChildItem $regPath) {
        $totalProducts++

        $netKeyPath = Join-Path $productKey.PSPath 'SourceList\Net'
        if (-not (Test-Path -LiteralPath $netKeyPath)) {
            continue  # helt normalt – ikke en fejl
        }

        $checkedProducts++
        $productInvalid = $false

        foreach ($sourceKey in Get-ChildItem $netKeyPath -ErrorAction SilentlyContinue) {

            $regItem = Get-Item $sourceKey.PSPath -ErrorAction SilentlyContinue
            if (-not $regItem) { continue }

            $sourcePath = $regItem.GetValue('')
            if ([string]::IsNullOrWhiteSpace($sourcePath)) { continue }

            $sourcePath = $sourcePath -replace '^n;1;',''

            if (-not (Test-Path -LiteralPath $sourcePath)) {
                $productInvalid = $true

                Write-Output "Product : $($productKey.PSChildName)"
                Write-Output "Missing : $sourcePath"
                Write-Output ""

                if ($DeleteInvalidSources) {
                    Remove-Item -LiteralPath $netKeyPath -Recurse -Force -ErrorAction SilentlyContinue
                    break
                }
            }
        }

        if ($productInvalid) { $invalidProducts++ }
    }

    Write-Output "Total products        : $totalProducts"
    Write-Output "Products with Net     : $checkedProducts"
    Write-Output "Products with errors  : $invalidProducts"
}
#endregion Test-SoftwareSources

#region Update-Notion
function Update-Notion {
    <#
    .SYNOPSIS
        Updates Notion application to the latest version.
    .DESCRIPTION
        Upgrades Notion using Winget package manager. Automatically closes any running Notion instances before upgrading.
    .OUTPUTS
        Displays upgrade status messages.
    .EXAMPLE
        Update-Notion
        Upgrades Notion to the latest version.
    #>
    # Check if Winget is installed
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Error "Winget is not installed. Please install Winget to proceed."
        return
    }
    # Check if Notion is already installed
    $notion_installed = winget list --name "Notion" | Select-String "Notion"
    if ($notion_installed) {
        # Upgrade Notion using Winget
        if (Get-Process -Name "Notion" -ErrorAction SilentlyContinue) {
            Write-Output "Notion is currently running. Closing Notion."
            Stop-Process -Name "Notion" -Force
        }
        Write-Output "Upgrade Notion..."
        winget upgrade --id=Notion.Notion -e --source=winget --override "/S /D=""C:\Program Files\Notion"""
        Write-Output "Notion installation completed."
    } else {
        Write-Output "Notion is not installed. Nothing to upgrade. Please install Notion first."
    }
}
#endregion Update-Notion

#region Watch-FileChange
function Watch-FileChange {
    <#
    .SYNOPSIS
        Monitors a file for changes and alerts on modification.
    .DESCRIPTION
        Continuously watches a file's last write time and alerts when it changes. Useful for monitoring log files or configuration changes. Press Ctrl+C to stop.
    .PARAMETER Path
        Specifies the file path to monitor.
    .EXAMPLE
        Watch-FileChange -Path "C:\Logs\app.log"
        Monitors the app log file for changes.
    #>
    param(
        [Parameter(Mandatory)]
        $Path
    )

    Write-Host "Monitoring file: $Path"
    Write-Host "Press Ctrl+C to stop."

    # Get initial timestamp
    $lastWrite = (Get-Item $Path).LastWriteTime

    while ($true) {
        $currentWrite = (Get-Item $Path).LastWriteTime

        if ($currentWrite -ne $lastWrite) {
            $lastWrite = $currentWrite

            Write-Host ""
            Write-Host "==========================================" -ForegroundColor Yellow
            Write-Host " FILE CHANGED: $($lastWrite)" -ForegroundColor Green
            Write-Host "==========================================" -ForegroundColor Yellow
            Write-Host ""

            Read-Host "Press Enter to continue monitoring..."
        }

        Start-Sleep -Milliseconds 300
    }
}
#endregion Watch-FileChange

#region Write-CheckFailed
Function Write-CheckFailed {
    <#
    .SYNOPSIS
        Writes a failure indicator (cross mark) to console.
    .DESCRIPTION
        Displays a red cross mark (✗) with optional prefix text for visual failure indicators.
    .PARAMETER Text
        Optional text to display before the cross mark.
    .EXAMPLE
        Write-CheckFailed -Text "Validation"
        Output: Validation ✗
    .EXAMPLE
        Write-CheckFailed
        Output: ✗
    #>
    param (
        [string]$Text
    )
    if ($null -ne $Text) {
        Write-Host -NoNewline "$Text "
    }
    Write-Host ([char]0x2717) -ForegroundColor Red # Unicode for cross mark
}
#endregion Write-CheckFailed

#region Write-CheckSucces
Function Write-CheckSucces {
    <#
    .SYNOPSIS
        Writes a success indicator (check mark) to console.
    .DESCRIPTION
        Displays a green check mark (✓) with optional prefix text for visual success indicators.
    .PARAMETER Text
        Optional text to display before the check mark.
    .EXAMPLE
        Write-CheckSucces -Text "Installation"
        Output: Installation ✓
    .EXAMPLE
        Write-CheckSucces
        Output: ✓
    #>
    param (
        [string]$Text
    )
    if ($null -ne $Text) {
        Write-Host -NoNewline "$Text "
    }
    Write-Host ([char]0x2713) -ForegroundColor Green # Unicode for check mark
}
#endregion Write-CheckSucces

#region Write-Log
function Write-Log {
    <#
    .SYNOPSIS
        Logs messages to a file in SCCM-style format with optional console output.
    .DESCRIPTION
        Writes standardized log entries with timestamp, component, user context, and severity level. Supports simultaneous file and console output (Host, Output, Verbose, or silent).
    .PARAMETER Path
        Specifies the log file path.
    .PARAMETER Message
        Specifies the message to log.
    .PARAMETER Component
        Specifies the component name for the log entry.
    .PARAMETER Type
        Specifies the severity type: Info, Warning, or Error.
    .PARAMETER OutputFormat
        Specifies output destination: Verbose, Host, Output, or None. Defaults to Verbose.
    .PARAMETER File
        Optional source file path to include in log entry.
    .EXAMPLE
        Write-Log -Path "C:\Logs\install.log" -Message "Install started" -Component "Setup" -Type Info
        Logs information message to file and outputs as verbose.
    .EXAMPLE
        Write-Log -Path "C:\Logs\install.log" -Message "Error occurred" -Component "Setup" -Type Error -OutputFormat Host
        Logs error to file and displays to console.
    #>
    # This log function is made to log installation and script events in a standardized way.
    # It logs in a .log file in a manner similar to SCCM (or at least very close to it)

    # It also allows simultaneous output of the same message, 
    # either as write-host, write-output, or write-verbose, as well as silent (none)
    # This way, you don't have to write 2 or more lines, one for the log and one/more for write-xxx

    #WARNING - There may be issues with add-content not being able to write to the log file - Try/catch does not seem to catch this...

    # Currently there is SilentlyContinue - So there is no logging on write errors. 
	# But if OutputFormat = Host|Output then output from write-log is still displayed on the screen
    [CmdletBinding()]
    Param(
          [parameter(Mandatory=$true)]
          [String]$Path,
          [String]$Message,
          [parameter(Mandatory=$true)]
          [String]$Component,
          [Parameter(Mandatory=$true)]
          [ValidateSet("Info", "Warning", "Error")]
          [String]$Type,
          [Parameter(Mandatory=$false)]
          [ValidateSet("Verbose", "Host", "Output","None")]
          [String]$OutputFormat = "Verbose",
          [parameter(Mandatory=$false)]
          [String]$File
    )

    switch ($Type) {
        "Info"    { [int]$Type = 1 }
        "Warning" { [int]$Type = 2 }
        "Error"   { [int]$Type = 3 }
    }

    # Make sure that the log directory exist
    $directory = $path | Split-Path -Parent #Extract folder from $path

    If((Test-Path $directory) -eq $false) {
        write-log -path "$LogFilePath"`
				  -Message "Opretter mappen $($directory)"`
				  -Component "$InstallType"`
				  -Type "info"`
				  -File "$PSScriptRoot"`
				  -OutputFormat "$OutputFormat"
        New-Item -Path $directory -ItemType Directory | Out-Null #Create folder
    }

    # Create a log entry
    $Content = "<![LOG[$Message]LOG]!>" +`
        "<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " +`
        "date=`"$(Get-Date -Format "M-d-yyyy")`" " +`
        "component=`"$Component`" " +`
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
        "type=`"$Type`" " +`
        "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
        "file=`"$File`">"

    switch ($OutputFormat)
    {
      Host {
        if ($Type -eq 1) { Write-Host $Message }
        if ($Type -eq 2) { Write-Warning $Message }
        if ($Type -eq 3) { Write-Error $Message }
      }

      Output {
        if ($Type -eq 1) { Write-Output $Message }
        if ($Type -eq 2) { Write-Warning $Message }
        if ($Type -eq 3) { Write-Error $Message }
      }

      Verbose {
        if ($Type -eq 1) { Write-Verbose $("Info: "+$Message)    }
        if ($Type -eq 2) { Write-Verbose $("Warning: "+$Message) }
        if ($Type -eq 3) { Write-Verbose $("Error: "+$Message)   }
      }

      None {
        #None makes no output to screen
      }
    }

    # Write the line to the log file
    Add-Content -Path $Path -Value $Content -ea silentlycontinue

    <#
        #$LogFilePath  = "C:\ProgramData\Installationlogs\Installer\Application.log"
        #write-log -path $LogFilePath -Message "This message is not dangerous" -Component "Good component" -Type "info" -File "$PSScriptRoot" -OutputFormat "Verbose"
        #write-log -path $LogFilePath -Message "This message is a bit toxic" -Component "Bad component" -Type "warning" -File "c:\temp\ninjascript.ps1" -OutputFormat "Host"
        #write-log -path $LogFilePath -Message "This message is dangerous" -Component "Very bad component" -Type "Error" -File "c:\temp\ninjascript.ps1" -OutputFormat "Output"
    #>
}
#endregion Write-Log

#region ProcessingAnimation
function ProcessingAnimation($scriptBlock) {
    <#
    .SYNOPSIS
        Displays an animated spinner while a script block executes.
    .DESCRIPTION
        Shows a rotating spinner animation at the current cursor position while running a background job. Automatically hides the spinner when the job completes.
    .PARAMETER scriptBlock
        Specifies the script block to execute in the background.
    .EXAMPLE
        ProcessingAnimation { Start-Sleep 5 }
        Shows spinner for 5 seconds.
    .EXAMPLE
        ProcessingAnimation { Get-ChildItem -Recurse -Path C:\ }
        Displays spinner while directory scan completes.
    #>
	$cursorTop = [Console]::CursorTop
	try {
	[Console]::CursorVisible = $false
	$counter = 0
	$frames = '|', '/', '-', '\'
	$jobName = Start-Job -ScriptBlock $scriptBlock
	while($jobName.JobStateInfo.State -eq "Running") {
	$frame = $frames[$counter % $frames.Length]
	Write-Host "$frame" -NoNewLine
	[Console]::SetCursorPosition(0, $cursorTop)
	$counter += 1
	Start-Sleep -Milliseconds 125
	}
	# Only needed if you use a multiline frames
	Write-Host ($frames[0] -replace '[^\s+]', ' ')
	}
	finally {
	[Console]::SetCursorPosition(0, $cursorTop)
	[Console]::CursorVisible = $true
	}
    # ProcessingAnimation { Start-Sleep 5 } 
}
#endregion ProcessingAnimation

#region Write-ToLog
Function Write-ToLog {
    <#
    .SYNOPSIS
        Writes log entries in RN standard format.
    .DESCRIPTION
        Logs messages in RN standardized format with component, timestamp, and thread ID information. Appends to specified log file in UTF-8 encoding.
    .PARAMETER Message
        Specifies the message to log.
    .PARAMETER Component
        Specifies the component name.
    .PARAMETER LogFilePath
        Specifies the log file path.
    .EXAMPLE
        Write-ToLog -Message "Backup started" -Component "Backup" -LogFilePath "C:\Logs\backup.log"
        Logs backup message to file.
    #>
    param (
        [Parameter(Mandatory=$true)]
        $Message,
        [Parameter(Mandatory=$true)]
        $Component,
        [Parameter(Mandatory=$true)]
        $LogFilePath)

    #https://confluence.rn.dk/display/KPP/L3+-+Placering+af+log+filer
    #RN log funktion - Simplificeret en smule af Dark (Path er nu kun én parameter)
    $Write = "{0} `$$<{1}><{2} {3}><thread={4}>" -f ($message), ($component), (Get-Date -Format "MM-dd-yyyy"), (Get-Date -Format "HH:mm:ss.ffffff"), $pid
    $Write | Out-File -Append -Encoding UTF8 -FilePath $LogFilePath
    #$LogFilePath  = "C:\ProgramData\Installationlogs\Installer\bomgar_standard.log"
    #Write-ToLog -Message "Dette er en god log" -Component "God komponent" -LogFilePath $LogFilePath
    #Write-ToLog -Message "Dette er en skidt log" -Component "Dårlig komponent" -LogFilePath $LogFilePath
}
#endregion Write-ToLog

function Import-Ods {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ Test-Path $_ })]
        [string]$FilePath,

        [string]$LibreOfficePath = "C:\Program Files\LibreOffice\program\soffice.exe"
    )

    DynamicParam {
        $cmd = Get-Command Import-Excel -CommandType Function

        $commonParams = @(
            'Verbose','Debug','ErrorAction','ErrorVariable',
            'WarningAction','WarningVariable','InformationAction',
            'InformationVariable','OutVariable','OutBuffer',
            'PipelineVariable','ProgressAction'
        )

        $exclude = $commonParams + @('Path','FilePath','LibreOfficePath')

        $dict = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()

        foreach ($param in $cmd.Parameters.Values) {
            if ($param.Name -in $exclude) { continue }

            $attrs = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()

            $paramAttr = [System.Management.Automation.ParameterAttribute]::new()
            $attrs.Add($paramAttr)

            $rdp = [System.Management.Automation.RuntimeDefinedParameter]::new(
                $param.Name,
                $param.ParameterType,
                $attrs
            )

            $dict.Add($param.Name, $rdp)
        }

        return $dict
    }

    begin {
        if (-not (Test-Path $LibreOfficePath)) {
            throw "LibreOffice (soffice.exe) blev ikke fundet: $LibreOfficePath"
        }

        $tempDir = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath()) -Name ([guid]::NewGuid())
        $tempXlsx = Join-Path $tempDir.FullName (
            [System.IO.Path]::GetFileNameWithoutExtension($FilePath) + ".xlsx"
        )
    }

    process {
        try {
            & $LibreOfficePath `
                --headless `
                --convert-to xlsx `
                --outdir $tempDir.FullName `
                $FilePath | Out-Null

            if (-not (Test-Path $tempXlsx)) {
                throw "Konvertering fejlede – XLSX blev ikke oprettet."
            }

            # Fjern egne parametre før videresendelse
            $importParams = @{} + $PSBoundParameters
            $importParams.Remove('FilePath')
            $importParams.Remove('LibreOfficePath')
            $importParams.Remove('Path')

            Import-Excel -Path $tempXlsx @importParams
        }
        finally {
            Remove-Item $tempDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}


Set-Alias -Name Import-Calc -Value Import-Ods
Set-Alias -Name Export-Calc -Value Export-Ods
Set-Alias -Name New-Calc -Value New-Ods
Set-Alias -Name Update-Calc -Value Update-Ods
Set-Alias -Name Remove-Calc -Value Remove-Ods
#Set-Alias -Name Clear-History -Value Invoke-CleanupHistory
Set-Alias -Name Pause-WithTimeout -Value Invoke-PauseWithTimeout
