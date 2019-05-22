function Retire-Application
{
    [CmdletBinding()]
    [Alias()]
    Param
    (
        # The display name of the application- when working with an application object- this will be the $_.localizedDisplayName
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
                   [Alias("localizedDisplayName","Application")]
        $Name= "",
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
                   [Alias("providerMachineName","SiteServerName")]
		$provider = "primary-site.domain.com",
		[Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=2)]
                   [Alias("siteCode")]
		$site = "ABC"

    )
    Begin{					  				  
			  $initParams = @{}
			  $initParams.Add("Verbose", $true) # Uncomment this line to enable verbose logging
			  $initParams.Add("ErrorAction", "Stop") # Uncomment this line to stop the script on any errors
			  $siteCode = $site # Site code 
			  $providerMachineName = $provider # SMS Provider machine name  
			  if((Get-Module ConfigurationManager) -eq $null) {Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams}
			  if((Get-PSDrive -Name $siteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams}         
			  Set-Location "$($SiteCode):\" @initParams
			  $dpGroup = @()
			  $dpGroup = @((Get-CMDistributionPointGroup).Name)
			  $dpName = @()
			  $dpName = @((Get-CMDistributionPointInfo).ServerName)
			  $Deployment = @()
			  $Deployment = @((Get-CMApplicationDeployment -Name $name).CollectionName)
		}
    Process{        
        ForEach ($Collection in $Deployment) {Remove-CMDeployment -ApplicationName $Name -CollectionName $Collection -force}                
        Remove-CMContentDistribution -ApplicationName $Name -DistributionPointGroupName $dpGroup -DistributionPointName $dpName -force
    }End{}        
}


