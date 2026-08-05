# PSScriptAnalyzer configuration for SandwormCheck.ps1.
#
# Each exclusion below is a deliberate design choice, not an oversight. They live
# here rather than as inline attributes because script-level suppression
# attributes are not valid PowerShell outside a function or param block.
@{
    ExcludeRules = @(
        # Script-level parameters are read inside functions through PowerShell's
        # scope chain, which the analyser does not follow.
        'PSReviewUnusedParameter',

        # Write-Host is the only way to emit per-severity colour. It is confined
        # to the colourised branch; the plain branch uses Write-Output, and colour
        # is disabled when stdout is redirected or -NoColor is passed.
        'PSAvoidUsingWriteHost',

        # Several functions genuinely return collections (Get-DefaultScanPaths,
        # Get-WalkedFiles); a singular name would misdescribe them.
        'PSUseSingularNouns',

        # SHA-1 is required because vendors published SHA-1 digests for this
        # campaign. It is used to match published indicators, never to establish
        # integrity or authenticity, so its collision weakness does not apply.
        # Removing it would drop real detection coverage.
        'PSAvoidUsingBrokenHashAlgorithms',

        # Add-Finding mutates an in-memory list only. This scanner is strictly
        # read-only and never changes system state, so -WhatIf/-Confirm would be
        # meaningless.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
