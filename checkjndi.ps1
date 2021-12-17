<#

.Description
Scans filesystem for .jar, war, and ear files that contains log4j code that may be vulnerable to CVE-2021-44228
Supply a top-level directory to begin searching, or default to the current directory.

.PARAMETER Toplevel
Top-level directory to begin search for jar files.

.EXAMPLE
PS> .\checkjindi.ps1
Scan the current directory and subdirectory for jar files.

.EXAMPLE
PS> .\checkjindi.ps1 c:\
Scan the entire c:\ drive for jar files.

.SYNOPSIS
Scans filesystem for .jar files that contains log4j code that may be vulnerable to CVE-2021-44228.
#>

#Requires -Version 3.0

param ([string]$toplevel)
Add-Type -Assembly 'System.IO.Compression.FileSystem'

function Get-Files {
    param (
        [string]$topdir
    )

    $jars = Get-ChildItem -Path $topdir -File -Recurse -Force -Include "*.jar","*.war","*.ear","*.zip","JndiLookup.class" -ErrorAction Ignore;

    return $jars
}

function Process-JAR {
    param (
        [Object]$jarfile,
        [String]$origfile = "",
        [String]$subjarfile = ""
    )
    try {
        $jar = [System.IO.Compression.ZipFile]::Open($jarfile, 'read');
    }
    catch {
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
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $TempFile, $true);
                if (Select-String -Path $TempFile -Pattern "JNDI is not supported"){
                    $ispatched = 1;
                }
            }
            catch {}
            Remove-Item $TempFile;
        }
        elseif ($entry.Name -like "*MessagePatternConverter.class"){
            $TempFile = [System.IO.Path]::GetTempFileName()
            try {
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $TempFile, $true);
                if (Select-String -Path $TempFile -Pattern "Message Lookups are no longer supported"){
                    $ispatched = 1;
                }
            }
            catch {}
            Remove-Item $TempFile;
        }
        elseif (($entry.Name -like "*.jar") -or ($entry.Name -like "*.war") -or ($entry.Name -like "*.ear") -or ($entry.Name -like "*.zip")) {
            if ($origfile -eq "")
            {
                $origfile = $jarfile.FullName
            }
            $TempFile = [System.IO.Path]::GetTempFileName()
            try {
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $TempFile, $true);
                Process-JAR $TempFile $origfile $entry.FullName;
            }
            catch{}
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
        Write-Warning $outputstring;
    }

}



$checkfiles = Get-Files $toplevel;
ForEach ($checkfile In $checkfiles) {
    if ($checkfile.Name -eq "JndiLookup.class")
    {
        Write-Warning "$checkfile *IS* JndiLookup.class"
    }
    else
    {
        Process-JAR $checkfile;
    }
}
