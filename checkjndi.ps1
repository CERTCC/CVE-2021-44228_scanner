<#PSScriptInfo

.VERSION 1.0.3

.GUID db424b6a-fdee-48e0-b0d5-3949e07c2ef6

.AUTHOR  https://github.com/CERTCC

.PROJECTURI https://github.com/CERTCC/CVE-2021-44228_scanner

.Description
Scans filesystem for .jar, war, ear, and zip files that contains log4j code that may be vulnerable to CVE-2021-44228
Supply a top-level directory to begin searching, or default to the current directory.

.PARAMETER Toplevel
Top-level directory to begin search for jar files.

.PARAMETER Force
Allows the Get-Childitem cmdlet to get items that otherwise can't be accessed by the user, such as hidden or system files. The Force parameter doesn't override security restrictions. Implementation varies among providers. For more information, see about_Providers.

.EXAMPLE
PS> .\checkjindi.ps1
Scan the current directory and subdirectory for jar files.

.EXAMPLE
PS> .\checkjindi.ps1 c:\
Scan the entire c:\ drive for jar files.

.SYNOPSIS
Scans filesystem for .jar files that contains log4j code that may be vulnerable to CVE-2021-44228.
#>
[CmdletBinding()]
param (
    # Specifies a path to one or more locations.
    [Parameter(Mandatory=$false,
               Position=0,
               ParameterSetName="Path",
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true,
               HelpMessage="Path to one or more locations.")]
    [Alias("PSPath")]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $toplevel = ".",
    #[string]$toplevel = ".",
    [switch] $Force = $false
    )

#Requires -Version 3.0

Begin {
    Add-Type -Assembly 'System.IO.Compression.FileSystem';
    $global:foundvulnerable = $false;

    function Get-Files {
        param (
            [string]$topdir
        )
            Get-ChildItem -Path $topdir -File -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable UnscannablePaths | Where-Object {($_.extension -eq ".jar") -or ($_.extension -eq ".war") -or ($_.extension -eq ".ear") -or ($_.extension -eq ".zip") -or ($_.Name -eq "JndiLookup.class")}
            foreach ($Exception in $UnscannablePaths) {
                Write-Warning "Unable to scan $($Exception.TargetObject) : $($Exception.FullyQualifiedErrorID)";
            }
    }

    function Process-JAR {
        param (
            [String]$jarfile,
            [String]$origfile = "",
            [String]$subjarfile = ""
        )
        try {
            $jar = [System.IO.Compression.ZipFile]::Open($jarfile, 'read');
        }
        catch {
            Write-Warning "Unable to scan $jarfile : $($_.FullyQualifiedErrorID)";
            return
        }
        [bool] $ispatched = 0;
        [bool] $hasjndi = 0;
        [string] $outputstring = "";

        ForEach ($entry in $jar.Entries) {
            #Write-Output $entry.Name;
            if($entry.Name -like "*JndiLookup.class"){
                if ($origfile -eq "")
                {
                    $hasjndi = 1;
                    $outputstring = "$jarfile contains $entry";
                }
                else
                {
                    $hasjndi = 1;
                    $outputstring = "$origfile contains $subjarfile contains $entry";
                }
                $TempFile = [System.IO.Path]::GetTempFileName()
                try {
                    Write-Verbose "Scanning $entry in $jarfile"
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $TempFile, $true);
                    if (Select-String -Path $TempFile -Pattern "JNDI is not supported"){
                        # 2.12.2 is patched
                        # https://github.com/apache/logging-log4j2/commit/70edc233343815d5efa043b54294a6fb065aa1c5#diff-4fde33b59714d0691a648fb2752ea1892502a815bdb40e83d3d6873abd163cdeR37
                        $ispatched = 1;
                    }
                }
                catch {
                    Write-Warning "Unable to scan $entry in $jarfile : $($_.FullyQualifiedErrorID)";
                }
                Remove-Item $TempFile;
            }
            elseif ($entry.Name -like "*MessagePatternConverter.class"){
                $TempFile = [System.IO.Path]::GetTempFileName();
                try {
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $TempFile, $true);
                    if (Select-String -Path $TempFile -Pattern "Message Lookups are no longer supported"){
                        # 2.16 is patched
                        # https://github.com/apache/logging-log4j2/commit/27972043b76c9645476f561c5adc483dec6d3f5d#diff-22ae074d2f9606392a3e3710b34967731a6ad3bc4012b42e0d362c9f87e0d65bR97
                        $ispatched = 1;
                    }
                }
                catch {
                    Write-Warning "Unable to scan $entry in $jarfile : $($_.FullyQualifiedErrorID)";
                }
                Remove-Item $TempFile;
            }
            elseif (($entry.Name -like "*.jar") -or ($entry.Name -like "*.war") -or ($entry.Name -like "*.ear") -or ($entry.Name -like "*.zip")) {
                if ($origfile -eq "")
                {
                    $origfile = $jarfile; #recurse embedded archive
                }
                $TempFile = [System.IO.Path]::GetTempFileName();
                try {
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $TempFile, $true);
                    Process-JAR $TempFile $origfile $entry.FullName;
                }
                catch{
                    Write-Warning "Unable to scan $entry in $jarfile : $($_.FullyQualifiedErrorID)";
                }
                Remove-Item $TempFile;

            }
        }
        $jar.Dispose();
        if ($ispatched){
            $outputstring = $outputstring + " ** BUT APPEARS TO BE PATCHED **";
        }
        if ($hasjndi -and $ispatched){
            Write-Host $outputstring;
        }
        elseif ($hasjndi){
            $global:foundvulnerable = $true;
            Write-Warning $outputstring;
        }

    }

    if (-not $Force) {
        Write-Warning "-Force not used, will not scan System or Hidden files.";
    }

}

Process {
    Write-Verbose "Scanning $toplevel"
    $checkfiles = Get-Files $toplevel;
    ForEach ($checkfile In $checkfiles) {
        if ($checkfile.Name -eq "JndiLookup.class")
        {
            Write-Host "$($checkfile.FullName) IS JndiLookup.class";
        }
        else
        {
            Process-JAR $checkfile.FullName;
        }
    }
}

End {

    if ($global:foundvulnerable -eq $false) {
        "No vulnerable components found";
    }

}
