<# 
 
.SYNOPSIS
    DSRegTool V2.2 PowerShell script.

.DESCRIPTION
    Device Registration Troubleshooter Tool is a PowerShell script that troubleshoots device registration common issues.

.AUTHOR:
    Mohammad Zmaili

.EXAMPLE
    .\DSRegTool.ps1

    Enter (1) to troubleshoot Azure AD Register

    Enter (2) to troubleshoot Azure AD Join device

    Enter (3) to troubleshoot Hybrid Azure AD Join

    Enter (4) to verify Service Connection Point (SCP)

    Enter (5) to verify the health status of the device

    Enter (6) to Verify Primary Refresh Token (PRT)

    Enter (7) to collect the logs

    Enter (Q) to Quit


#>

Function Test-DevRegConnectivity($Write){
    $TestConnResult=@()
    If($Write){Write-Host}
    If($Write){Write-Host "Testing Internet Connectivity..." -ForegroundColor Yellow}
    $ErrorActionPreference= 'silentlycontinue'
    $global:TestFailed=$false

    $global:ProxyServer = checkProxy $Write
    If($Write){Write-Host}
    If($Write){Write-Host "Testing Device Registration Endpoints..." -ForegroundColor Yellow}
    if ($global:ProxyServer -eq "NoProxy"){
        $PSScript = "(Invoke-WebRequest -uri 'login.microsoftonline.com' -UseBasicParsing).StatusCode"
        $TestResult = RunPScript -PSScript $PSScript
        if ($TestResult -eq 200){
            If($Write){Write-Host "Connection to login.microsoftonline.com .............. Succeeded." -ForegroundColor Green }
            $TestConnResult = $TestConnResult + "Connection to login.microsoftonline.com .............. Succeeded."
        }else{
            $global:TestFailed=$true
            If($Write){Write-Host "Connection to login.microsoftonline.com ................. failed." -ForegroundColor Red }
            $TestConnResult = $TestConnResult + "Connection to login.microsoftonline.com ................. failed."
        }
        $PSScript = "(Invoke-WebRequest -uri 'device.login.microsoftonline.com' -UseBasicParsing).StatusCode"
        $TestResult = RunPScript -PSScript $PSScript
        if ($TestResult -eq 200){
            If($Write){Write-Host "Connection to device.login.microsoftonline.com ......  Succeeded." -ForegroundColor Green }
            $TestConnResult = $TestConnResult + "Connection to device.login.microsoftonline.com ......  Succeeded."
        }else{
            $global:TestFailed=$true
            If($Write){Write-Host "Connection to device.login.microsoftonline.com .......... failed." -ForegroundColor Red }
            $TestConnResult = $TestConnResult + "Connection to device.login.microsoftonline.com .......... failed."
        }

        $PSScript = "(Invoke-WebRequest -uri 'https://enterpriseregistration.windows.net/$global:TenantName/discover?api-version=1.7' -UseBasicParsing -Headers @{'Accept' = 'application/json'; 'ocp-adrs-client-name' = 'dsreg'; 'ocp-adrs-client-version' = '10'}).StatusCode"
        $TestResult = RunPScript -PSScript $PSScript
        if ($TestResult -eq 200){
            If($Write){Write-Host "Connection to enterpriseregistration.windows.net ..... Succeeded." -ForegroundColor Green }
            $TestConnResult = $TestConnResult + "Connection to enterpriseregistration.windows.net ..... Succeeded."
        }else{
            $global:TestFailed=$true
            If($Write){Write-Host "Connection to enterpriseregistration.windows.net ........ failed." -ForegroundColor Red }
            $TestConnResult = $TestConnResult + "Connection to enterpriseregistration.windows.net ........ failed."
        }
    }else{
        if ($global:login){
            $PSScript = "(Invoke-WebRequest -uri 'login.microsoftonline.com' -UseBasicParsing).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }else{
            $PSScript = "(Invoke-WebRequest -uri 'login.microsoftonline.com' -UseBasicParsing -Proxy $global:ProxyServer).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }
        if ($TestResult -eq 200){
            If($Write){Write-Host "Connection to login.microsoftonline.com .............. Succeeded." -ForegroundColor Green }
            $TestConnResult = $TestConnResult + "Connection to login.microsoftonline.com .............. Succeeded."
        }else{
            $global:TestFailed=$true
            If($Write){Write-Host "Connection to login.microsoftonline.com ................. failed." -ForegroundColor Red }
            $TestConnResult = $TestConnResult + "Connection to login.microsoftonline.com ................. failed."
        }

        if ($global:device){
            $PSScript = "(Invoke-WebRequest -uri 'device.login.microsoftonline.com' -UseBasicParsing).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }else{
            $PSScript = "(Invoke-WebRequest -uri 'device.login.microsoftonline.com' -UseBasicParsing -Proxy $global:ProxyServer).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }
        if ($TestResult -eq 200){
            If($Write){Write-Host "Connection to device.login.microsoftonline.com ......  Succeeded." -ForegroundColor Green }
            $TestConnResult = $TestConnResult + "Connection to device.login.microsoftonline.com ......  Succeeded."
        }else{
            $global:TestFailed=$true
            If($Write){Write-Host "Connection to device.login.microsoftonline.com .......... failed." -ForegroundColor Red }
            $TestConnResult = $TestConnResult + "Connection to device.login.microsoftonline.com .......... failed."
        }

        if ($global:enterprise){
            $PSScript = "(Invoke-WebRequest -uri 'https://enterpriseregistration.windows.net/microsoft.com/discover?api-version=1.7' -UseBasicParsing -Headers @{'Accept' = 'application/json'; 'ocp-adrs-client-name' = 'dsreg'; 'ocp-adrs-client-version' = '10'}).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }else{
            $PSScript = "(Invoke-WebRequest -uri 'https://enterpriseregistration.windows.net/microsoft.com/discover?api-version=1.7' -UseBasicParsing -Proxy $global:ProxyServer -Headers @{'Accept' = 'application/json'; 'ocp-adrs-client-name' = 'dsreg'; 'ocp-adrs-client-version' = '10'}).StatusCode"
            $TestResult = RunPScript -PSScript $PSScript
        }
        if ($TestResult -eq 200){
            If($Write){Write-Host "Connection to enterpriseregistration.windows.net ..... Succeeded." -ForegroundColor Green }
            $TestConnResult = $TestConnResult + "Connection to enterpriseregistration.windows.net ..... Succeeded."
        }else{
            $global:TestFailed=$true
            If($Write){Write-Host "Connection to enterpriseregistration.windows.net ........ failed." -ForegroundColor Red }
            $TestConnResult = $TestConnResult + "Connection to enterpriseregistration.windows.net ........ failed."
        }
    }
    return $TestConnResult
}

Function CheckePRT{
    ''
    Write-Host "Testing Enterprise PRT..." -ForegroundColor Yellow
    $ePRT = $DSReg | Select-String EnterprisePrt | select-object -First 1
    $ePRT = ($ePRT.tostring() -split ":")[1].trim()
    if ($ePRT -eq 'YES'){
        $hostname = hostname
        Write-Host $hostname "device does have Enterprise PRT" -ForegroundColor Green -BackgroundColor Black
    }else{
        $hostname = hostname
        Write-Host $hostname "device does NOT have Enterprise PRT" -ForegroundColor Yellow -BackgroundColor Black
    }

}

Function PSasAdmin{
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())    $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Function CheckPRT{
''
Write-Host "Testing if PowerShell running with elevated privileges..." -ForegroundColor Yellow
if (PSasAdmin){
    # PS running as admin.
    Write-Host "PowerShell is running with elevated privileges" -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: This test needs to be running with normal privileges" -ForegroundColor Yellow -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}else{
    Write-Host "PowerShell is running with normal privileges" -ForegroundColor Green -BackgroundColor Black
}


    #Check OS version:
    ''
    Write-Host "Testing OS version..." -ForegroundColor Yellow
    $OSVersoin = ([environment]::OSVersion.Version).major
    $OSBuild = ([environment]::OSVersion.Version).Build
    if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
        Write-Host "Test passed: device has current OS version." -ForegroundColor Green -BackgroundColor Black

    }else{
        # dsregcmd will not work.
        Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
        ''
        Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit
    }

    #Check dsregcmd status.
    $DSReg = dsregcmd /status

    ''
    Write-Host "Testing if the device joined to the local domain..." -ForegroundColor Yellow
    $DJ = $DSReg | Select-String DomainJoin
    $DJ = ($DJ.tostring() -split ":")[1].trim()
    if ($DJ -ne "YES"){
        $hostname = hostname
        Write-Host $hostname "device is NOT joined to the local domain" -ForegroundColor Yellow -BackgroundColor Black
    }else{
        #The device is joined to the local domain.
        $IS_DJ = $true
        $DomainName = $DSReg | Select-String DomainName 
        $DomainName =($DomainName.tostring() -split ":")[1].trim()
        $hostname = hostname
        Write-Host $hostname "device is joined to the local domain that has the name of" $DomainName -ForegroundColor Yellow -BackgroundColor Black
    }    

    #Checking if the device connected to AzureAD
    if ($DJ -eq 'YES'){
        #Check if the device is hybrid
        ''
        Write-Host "Testing if the device is Hybrid Azure AD joined..." -ForegroundColor Yellow
        $AADJ = $DSReg | Select-String AzureAdJoined
        $AADJ = ($AADJ.tostring() -split ":")[1].trim()
        if ($AADJ -eq 'YES'){
            #The device is hybrid
            $hostname = hostname
            Write-Host $hostname "device is Hybrid Azure AD joined" -ForegroundColor Green -BackgroundColor Black
            #CheckPRT value
            ''
            Write-Host "Testing Azure AD PRT..." -ForegroundColor Yellow
            $ADPRT = $DSReg | Select-String AzureAdPrt | select-object -First 1
            $ADPRT = ($ADPRT.tostring() -split ":")[1].Trim()
            if ($ADPRT -eq 'YES'){
                #PRT is available
                Write-Host "Test passed: Azure AD PRT is available on this device for the looged on user" -ForegroundColor Green -BackgroundColor Black
                CheckePRT
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
            }else{
                #PRT not available
                Write-Host "Test failed: Azure AD PRT is not available. Hence SSO is not working and the device may be blocked if you have Conditional Access Policy requires the user to sign-in from trusted device" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: lock the device and unlock it and run the script again. If the issue remains, collect the logs and send them to MS support" -ForegroundColor Yellow
                CheckePRT
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
            }

            exit
        }else{
           $hostname = hostname
           Write-Host $hostname "device is NOT Hybrid Azure AD joined" -ForegroundColor Yellow -BackgroundColor Black
           #Check WPJ
           ''
           Write-Host "Testing if the device is workplace joined..." -ForegroundColor Yellow
           $WPJ = $DSReg | Select-String WorkplaceJoined | Select-Object -First 1
           $WPJ = ($WPJ.tostring() -split ":")[1].trim()
           if ($WPJ -eq 'YES'){
                #Device is WPJ, check the registry
                $hostname = hostname
                Write-Host $hostname "device is workplace joined" -ForegroundColor Green -BackgroundColor Black
                ###check registry
           }else{
                $hostname = hostname
                Write-Host $hostname "device is NOT workplace joined" -ForegroundColor Yellow -BackgroundColor Black
                Write-Host "Test failed:" $hostname "device is NOT connected to Azure AD, hence PRT is not valid" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: make sure the device is connected to AAD to get Azure PRT" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit        
           }
        }
        
    }else{
        #Check if the device AADJ
        ''
        Write-Host "Testing if the device is Azure AD Joined..." -ForegroundColor Yellow
        $AADJ = $DSReg | Select-String AzureAdJoined
        $AADJ = ($AADJ.tostring() -split ":")[1].trim()
        if ($AADJ -eq 'YES'){
            #The device AADJ
            $hostname = hostname
            Write-Host $hostname "device is Azure AD joined" -ForegroundColor Green -BackgroundColor Black
            #CheckPRT value
            ''
            Write-Host "Testing Azure AD PRT..." -ForegroundColor Yellow
            $ADPRT = $DSReg | Select-String AzureAdPrt | select-object -First 1
            $ADPRT = ($ADPRT.tostring() -split ":")[1].Trim()
            if ($ADPRT -eq 'YES'){
                #PRT is available
                Write-Host "Test passed: Azure AD PRT is available on this device for the looged on user" -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
            }else{
                #PRT not available
                Write-Host "Test failed: Azure AD PRT is not available. Hence SSO with O365 services is not working and the device may be blocked if you have Conditional Access Policy requires the user to sign-in from trusted device" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: lock the device and unlock it and run the script again. If the issue remains, collect the logs and send them to MS support" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
            }

           exit
        }else{
           $hostname = hostname
           Write-Host $hostname "device is NOT Azure AD joined" -ForegroundColor Yellow -BackgroundColor Black
           #Check WPJ
           ''
           Write-Host "Testing if the device is workplace joined..." -ForegroundColor Yellow
           $WPJ = $DSReg | Select-String WorkplaceJoined
           $WPJ = ($WPJ.tostring() -split ":")[1].trim()
           if ($WPJ -eq 'YES'){
                #Device is WPJ, check the registry
                $hostname = hostname
                Write-Host $hostname "device is workplace joined" -ForegroundColor Green -BackgroundColor Black
                ###check registry
           }else{
                $hostname = hostname
                Write-Host $hostname "device is NOT workplace joined" -ForegroundColor Yellow -BackgroundColor Black
                Write-Host "Test failed:" $hostname "device is NOT connected to Azure AD, hence PRT is not valid" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: make sure the device is connected to AAD to get Azure PRT" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit        
           }
        }
    }
}

Function checkProxy($Write){
# Check Proxy settings
If($Write){Write-Host "Checking winHTTP proxy settings..." -ForegroundColor Yellow}
$global:ProxyServer="NoProxy"
$winHTTP = netsh winhttp show proxy
$Proxy = $winHTTP | Select-String server
$global:ProxyServer=$Proxy.ToString().TrimStart("Proxy Server(s) :  ")
$global:Bypass = $winHTTP | Select-String Bypass
$global:Bypass=$global:Bypass.ToString().TrimStart("Bypass List     :  ")

if ($global:ProxyServer -eq "Direct access (no proxy server)."){
    $global:ProxyServer="NoProxy"
    If($Write){Write-Host "Access Type : DIRECT"}
}

if ( ($global:ProxyServer -ne "NoProxy") -and (-not($global:ProxyServer.StartsWith("http://")))){
    If($Write){Write-Host "      Access Type : PROXY"}
    If($Write){Write-Host "Proxy Server List :" $global:ProxyServer}
    If($Write){Write-Host "Proxy Bypass List :" $global:Bypass}
    $global:ProxyServer = "http://" + $global:ProxyServer
}

$global:login= $global:Bypass.Contains("*.microsoftonline.com") -or $global:Bypass.Contains("login.microsoftonline.com")

$global:device= $global:Bypass.Contains("*.microsoftonline.com") -or $global:Bypass.Contains("*.login.microsoftonline.com") -or $global:Bypass.Contains("device.login.microsoftonline.com")

$global:enterprise= $global:Bypass.Contains("*.windows.net") -or $global:Bypass.Contains("enterpriseregistration.windows.net")

return $global:ProxyServer
}

Function WPJTS{
    #Check OS version:
    ''
    Write-Host "Testing OS version..." -ForegroundColor Yellow
    $OSVersoin = ([environment]::OSVersion.Version).major
    $OSBuild = ([environment]::OSVersion.Version).Build
    if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
        Write-Host "Test passed: device has current OS version." -ForegroundColor Green -BackgroundColor Black

    }else{
        # dsregcmd will not work.
        Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
        ''
        Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit
    }


#Check dsregcmd status.
$DSReg = dsregcmd /status

#Checking if the device connected to AzureAD
''
Write-Host "Testing if the device is Azure AD Registered..." -ForegroundColor Yellow
$WPJ = $DSReg | Select-String WorkplaceJoined | Select-Object -First 1
$WPJ = ($WPJ.tostring() -split ":")[1].trim()
if ($WPJ -ne "YES"){
    #The device is not connected to AAD:
    ### perform WPJ (all other tests should be here)
    Write-Host "Test failed:" $hostname "device is NOT connected to Azure AD as Azure AD Registered device" -ForegroundColor Red -BackgroundColor Black
        
    #Checking Internet connectivity
    ''
    Write-Host "Testing Internet Connectivity..." -ForegroundColor Yellow
    $InternetConn1=$true
    $InternetConn2=$true
    $InternetConn3=$true
    $TestResult = (Test-NetConnection -ComputerName login.microsoftonline.com -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to login.microsoftonline.com .............. Succeeded." -ForegroundColor Green
    }else{
        Write-Host "Connection to login.microsoftonline.com ................. failed." -ForegroundColor Red 
        $InternetConn1=$false
    }

    
    $TestResult = (Test-NetConnection -ComputerName device.login.microsoftonline.com -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to device.login.microsoftonline.com ......  Succeeded." -ForegroundColor Green 
    }else{
        Write-Host "Connection to device.login.microsoftonline.com .......... failed." -ForegroundColor Red 
        $InternetConn2=$false
    }


    $TestResult = (Test-NetConnection -ComputerName enterpriseregistration.windows.net -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to enterpriseregistration.windows.net ..... Succeeded." -ForegroundColor Green 
    }else{
        Write-Host "Connection to enterpriseregistration.windows.net ........ failed." -ForegroundColor Red 
        $InternetConn3=$false
    }

    if (($InternetConn1 -eq $true) -or ($InternetConn2 -eq $true) -or ($InternetConn3 -eq $true) ){
        Write-Host "Test passed: user is able to communicate with MS endpoints successfully" -ForegroundColor Green -BackgroundColor Black
    }else{
        Write-Host "Test failed: user is not able to communicate with MS endpoints" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended action: make sure that the user is able to communicate with the above MS endpoints successfully" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit                
    }

    CheckMSOnline

    #Check DevReg app
    ''
    Write-Host "Testing Device Registration Service..." -ForegroundColor Yellow
    if ((Get-MsolServicePrincipal -AppPrincipalId 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9).accountenabled){
       Write-Host "Test passed: Device Registration Service is enabled on the tenant" -ForegroundColor Green -BackgroundColor Black 
    }else{
        Write-Host "Test failed: Device Registration Service is disabled on the tenant" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended action: enable Device Registration Service application on your tenant" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit                
    }

    ''
    ''
    Write-Host "All tests completed successfully. You can start registering your device to Azure AD." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}else{
    #The device is WPJ join
    $TenantName = $DSReg | Select-String WorkplaceTenantName
    $TenantName =($TenantName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host "Test passed:" $hostname "device is connected to Azure AD tenant that has the name of" $TenantName "as Azure AD Register device" -ForegroundColor Green -BackgroundColor Black

}

''
Write-Host "Testing the device status on Azure AD..." -ForegroundColor Yellow

CheckMSOnline

#Check the device status on AAD:
$DID = $DSReg | Select-String WorkplaceDeviceId
$DID = ($DID.ToString() -split ":")[1].Trim()
$AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
#Check if the device exist:
''
Write-Host "Checking if device exist in AAD..." -ForegroundColor Yellow
if ($AADDevice.count -ge 1){
    #The device existing in AAD:
    Write-Host "Test passed: the device object exists on Azure AD." -ForegroundColor Green -BackgroundColor Black
}else{
    #Device does not exist:
    ###Reregister device to AAD
    Write-Host "Test failed: the device does not exist in your Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Disconnect the device from Azure AD form 'settings > Accounts > Access work or school' and then connect it again to AAD." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}

#Check if the device is enabled:
''
Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
if ($AADDevice.Enabled -eq $false){
    ###Enabling device in AAD
    Write-Host "Test failed: the device is not enabled on Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}else{
    Write-Host "Test passed: the device is enabled on Azure AD tenant." -ForegroundColor Green -BackgroundColor Black
}


''
''
Write-Host "The device is connected to AAD as Azure AD Registered device, and it is in healthty state." -ForegroundColor Green -BackgroundColor Black
''
''
Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
''
''
    
}#end WPJTS

Function AADJ{
#Check PSAdmin
''
Write-Host "Testing if PowerShell running with elevated privileges..." -ForegroundColor Yellow 
if (PSasAdmin){
    # PS running as admin.
    Write-Host "PowerShell is running with elevated privileges" -ForegroundColor Green -BackgroundColor Black
}else{
    Write-Host "PowerShell is NOT running with elevated privileges" -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: This test needs to be running with elevated privileges" -ForegroundColor Yellow -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}
#Check OS version:
''
Write-Host "Testing OS version..." -ForegroundColor Yellow
$OSVersoin = ([environment]::OSVersion.Version).major
$OSBuild = ([environment]::OSVersion.Version).Build
if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
    Write-Host "Test passed: device has current OS version." -ForegroundColor Green -BackgroundColor Black

}else{
    # dsregcmd will not work.
    Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
    ''
    Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}


#Check dsregcmd status.
$DSReg = dsregcmd /status

''
Write-Host "Testing if the device joined to the local domain..." -ForegroundColor Yellow
$DJ = $DSReg | Select-String DomainJoin
$DJ = ($DJ.tostring() -split ":")[1].trim()
if ($DJ -ne "YES"){
    $hostname = hostname
    Write-Host $hostname "device is NOT joined to the local domain" -ForegroundColor Yellow -BackgroundColor Black
}else{
    #The device is joined to the local domain.
    $DomainName = $DSReg | Select-String DomainName 
    $DomainName =($DomainName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host $hostname "device is joined to the local domain that has the name of" $DomainName -ForegroundColor Yellow -BackgroundColor Black
    ''
    Write-Host "Recommended action: the selected option runs for AADJ devices. To troubleshoot hybrid devices, rerun the script and select option '3'." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}    

#Checking if the device connected to AzureAD
''
Write-Host "Testing if the device is joined to AzureAD..." -ForegroundColor Yellow
$AADJ = $DSReg | Select-String AzureAdJoined
$AADJ = ($AADJ.tostring() -split ":")[1].trim()
if ($AADJ -ne "YES"){
    #The device is not connected to AAD:
    ### perform AADJ (all other tests should be here)
    Write-Host "Test failed:" $hostname "device is NOT connected to Azure AD" -ForegroundColor Red -BackgroundColor Black

    #Checking if the user is bulitin admin
    ''
    Write-Host "Testing if you signed in user is a Built-in Administrator account..." -ForegroundColor Yellow
    $BAdmin=(Get-LocalUser | where{$_.SID -like "*-500"}).name
    $LUser=$env:username
    if ($BAdmin -eq $LUser){
        Write-Host "Test failed: you signed in using the built-in Administrator account" -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: create a different local account before you use Azure Active Directory join to finish the setup." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit        
    }else{
        Write-Host "Test passed: you are not signed in using the built-in Administrator account" -ForegroundColor Green -BackgroundColor Black
    }


    #Checking if the signed in user is a local admin
    ''
    Write-Host "Testing if the signed in user has local admin permissions..." -ForegroundColor Yellow
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        Write-Host "Test passed: the signed in user has local admin permissions" -ForegroundColor Green -BackgroundColor Black
    }else{
        Write-Host "Test failed: the signed in user does NOT have local admin permissions" -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: sign in with a user that has local admin permissions before you start joining the device to Azure AD to finish the setup" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit        

    }

        
    #Checking Internet connectivity
    ''
    Write-Host "Testing Internet Connectivity..." -ForegroundColor Yellow
    $InternetConn1=$true
    $InternetConn2=$true
    $InternetConn3=$true
    $TestResult = (Test-NetConnection -ComputerName login.microsoftonline.com -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to login.microsoftonline.com .............. Succeeded." -ForegroundColor Green
    }else{
        Write-Host "Connection to login.microsoftonline.com ................. failed." -ForegroundColor Red 
        $InternetConn1=$false
    }

    
    $TestResult = (Test-NetConnection -ComputerName device.login.microsoftonline.com -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to device.login.microsoftonline.com ......  Succeeded." -ForegroundColor Green 
    }else{
        Write-Host "Connection to device.login.microsoftonline.com .......... failed." -ForegroundColor Red 
        $InternetConn2=$false
    }


    $TestResult = (Test-NetConnection -ComputerName enterpriseregistration.windows.net -Port 443).TcpTestSucceeded
    if ($TestResult -eq $true){
        Write-Host "Connection to enterpriseregistration.windows.net ..... Succeeded." -ForegroundColor Green 
    }else{
        Write-Host "Connection to enterpriseregistration.windows.net ........ failed." -ForegroundColor Red 
        $InternetConn3=$false
    }

    if (($InternetConn1 -eq $true) -or ($InternetConn2 -eq $true) -or ($InternetConn3 -eq $true) ){
        Write-Host "Test passed: user is able to communicate with MS endpoints successfully" -ForegroundColor Green -BackgroundColor Black
    }else{
        Write-Host "Test failed: user is not able to communicate with MS endpoints" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended action: make sure that the user is able to communicate with the above MS endpoints successfully" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit                
    }

    CheckMSOnline

    #Check DevReg app
    ''
    Write-Host "Testing Device Registration Service..." -ForegroundColor Yellow
    if ((Get-MsolServicePrincipal -AppPrincipalId 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9).accountenabled){
       Write-Host "Test passed: Device Registration Service is enabled on the tenant" -ForegroundColor Green -BackgroundColor Black 
    }else{
        Write-Host "Test failed: Device Registration Service is disabled on the tenant" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended action: enable Device Registration Service application on your tenant" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit                
    }

    ''
    ''
    Write-Host "All tests completed successfully. You can start joining your device to Azure AD." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}else{
    #The device is AAD join
    $TenantName = $DSReg | Select-String TenantName | Select-Object -first 1
    $TenantName =($TenantName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host "Test passed:" $hostname "device is joined to Azure AD tenant that has the name of" $TenantName -ForegroundColor Green -BackgroundColor Black

}

''
Write-Host "Testing the device status on Azure AD..." -ForegroundColor Yellow

CheckMSOnline

#Check the device status on AAD:
$DID = $DSReg | Select-String DeviceId
$DID = ($DID.ToString() -split ":")[1].Trim()
$AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
#Check if the device exist:
''
Write-Host "Checking if device exist in AAD..." -ForegroundColor Yellow
if ($AADDevice.count -ge 1){
    #The device existing in AAD:
    Write-Host "Test passed: the device object exists on Azure AD." -ForegroundColor Green -BackgroundColor Black
}else{
    #Device does not exist:
    ###Rejoin device to AAD
    Write-Host "Test failed: the device does not exist in your Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again. If you have a Managed domain, make sure the device is in the sync scope." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}

#Check if the device is enabled:
''
Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
if ($AADDevice.Enabled -eq $false){
    ###Enabling device in AAD
    Write-Host "Test failed: the device is not enabled on Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}else{
        Write-Host "Test passed: the device is enabled on Azure AD tenant." -ForegroundColor Green -BackgroundColor Black
}


''
''
Write-Host "The device is connected to AAD as Azure AD joined device, and it is in healthty state." -ForegroundColor Green -BackgroundColor Black
''
''
Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
''
''    
#end AADJ
}

Function VerifySCP{
  #Check client-side registry setting for SCP
    $SCPClient=$false
    ''
    Write-Host "Testing client-side registry setting for SCP..." -ForegroundColor Yellow
    $Reg=Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD -ErrorAction SilentlyContinue
    if (((($Reg.TenantId).Length) -eq 0) -AND ((($Reg.TenantName).Length) -eq 0)) {
       Write-Host "Client-side registry setting for SCP is not configured" -ForegroundColor Yellow -BackgroundColor Black
    }else{
        $SCPClient=$true
        Write-Host "Client-side registry setting for SCP is configured as the following:" -ForegroundColor Green -BackgroundColor Black
        Write-Host "TenantId:" $Reg.TenantId
        $global:TenantName = $Reg.TenantName
        Write-Host "TenantName:" $Reg.TenantName
        #Check client-side SCP info
        ''
        Write-Host "Testing client-side registry configuration..." -ForegroundColor Yellow
        CheckMSOnline
        Write-Host "Checking Tenant ID..." -ForegroundColor Yellow
        $TenantID=((Get-MsolAccountSku).accountobjectid).Guid | Select-Object -first 1
        if ($TenantID -eq $Reg.TenantId){
            Write-Host "Tenant ID is configured correctly" -ForegroundColor Green -BackgroundColor Black
            ''
            Write-Host "Checking Tenant Name..." -ForegroundColor Yellow
            $TNConfigured=$false
            $TName=Get-MsolDomain | where Status -eq Verified
            foreach($TN in $TName.name){
                if ($TN -eq $Reg.TenantName){
                    $TNConfigured =$true
                    $global:DomainAuthType = $TName.Authentication
                    try{
                        $global:MEXURL =  Get-MsolDomainFederationSettings -DomainName $TName.name -ErrorAction Stop
                        $global:MEXURL = $global:MEXURL.MetadataExchangeUri
                    }catch{
                        $global:MEXURLRun=$false
                    }
                }
            }
            if ($TNConfigured -eq $true){
                Write-Host "Tenant Name is configured correctly" -ForegroundColor Green -BackgroundColor Black
            }else{
                Write-Host "Test failed: Tenant Name is not configured correctly" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: Make sure the Tenant Name is configured correctly in registry." -ForegroundColor Yellow
                Write-Host "     Registry path: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit
            }

        }else{
            Write-Host "Test failed: Tenant ID is not configured correctly" -ForegroundColor Red -BackgroundColor Black
            ''
            Write-Host "Recommended action: Make sure the Tenant ID is configured correctly in registry." -ForegroundColor Yellow
            Write-Host "     Registry path: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD" -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
        }


    }

    #Check connectivity to DC
    $global:DCTestPerformed=$true
    ''
    Write-Host "Testing Domain Controller connectivity..." -ForegroundColor Yellow
    $Root = [ADSI]"LDAP://RootDSE"
    $ConfigurationName = $Root.rootDomainNamingContext
    if (($ConfigurationName.length) -eq 0){
        Write-Host "Test failed: connection to Domain Controller failed" -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: Make sure that the device has a line of sight to the Domain controller" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit        
    }else{
        Write-Host "Test passed: connection to Domain Controller succeeded" -ForegroundColor Green -BackgroundColor Black
    }


    #Check SCP
    if ($SCPClient -eq $false){
        ''
        Write-Host "Checking Service Connection Point (SCP)..." -ForegroundColor Yellow

        $Root = [ADSI]"LDAP://RootDSE"
        $ConfigurationName = $Root.rootDomainNamingContext
        $scp = New-Object System.DirectoryServices.DirectoryEntry;
        $scp.Path = "LDAP://CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services,CN=Configuration," + $ConfigurationName;
        if ($scp.Keywords -ne $null){
            Write-Host "Service Connection Point (SCP) is configured as following:" -ForegroundColor Green -BackgroundColor Black
            $scp.Keywords
            #check SCP
            ''
            Write-Host "Testing Service Connection Point (SCP) configuration..." -ForegroundColor Yellow
            $TID = $scp.Keywords | Select-String azureADId
            $TID = ($TID.tostring() -split ":")[1].trim()

            $TN = $scp.Keywords | Select-String azureADName
            $TN = ($TN.tostring() -split ":")[1].trim()
            $global:TenantName = $TN
            CheckMSOnline
            Write-Host "Checking Tenant ID..." -ForegroundColor Yellow
            $TenantID=((Get-MsolAccountSku).accountobjectid).Guid | Select-Object -first 1
            if ($TenantID -eq $TID){
                Write-Host "Tenant ID is configured correctly" -ForegroundColor Green -BackgroundColor Black
                ''
                Write-Host "Checking Tenant Name..." -ForegroundColor Yellow
                $TNConfigured=$false
                $TNames=Get-MsolDomain | where Status -eq Verified
                foreach($TName in $TNames){
                    if ($TName.name -eq $TN){
                        $TNConfigured =$true
                        $global:DomainAuthType = $TName.Authentication
                        try{
                            $global:MEXURL =  Get-MsolDomainFederationSettings -DomainName $TName.name -ErrorAction Stop
                            $global:MEXURL = $global:MEXURL.MetadataExchangeUri
                        }catch{
                            $global:MEXURLRun=$false
                        }

                    }
                }
                if ($TNConfigured -eq $true){
                    Write-Host "Tenant Name is configured correctly" -ForegroundColor Green -BackgroundColor Black
                }else{
                    Write-Host "Test failed: Tenant Name is not configured correctly" -ForegroundColor Red -BackgroundColor Black
                    ''
                    Write-Host "Recommended action: Make sure the Tenant Name is configured correctly in SCP." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit
                }
            }else{
                Write-Host "Test failed: Tenant ID is not configured correctly" -ForegroundColor Red -BackgroundColor Black
                ''
                Write-Host "Recommended action: Make sure the Tenant ID is configured correctly in SCP." -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit
            }

        }else{
            Write-Host "Service Connection Point is not configured in your forest" -ForegroundColor red -BackgroundColor Black
            ''
            Write-Host "Recommended action: make sure to configure SCP in your forest" -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }
    }
}

#Log Collection functions
Function ExportEventViewerLogs ($EventViewerLogs,$ExportPath){
    ForEach ($EventViewerLog in $EventViewerLogs){		$EventViewerLogAfter = [regex]::Replace($EventViewerLog,"/","-")		$ExportedFileName = $ExportPath +"\"+ $EventViewerLogAfter+".evtx"
        (New-Object System.Diagnostics.Eventing.Reader.EventLogSession).ExportLogAndMessages($EventViewerLog,'LogName','*',$ExportedFileName)    }
}

Function EnableDebugEvents ($DbgEvents){    ForEach ($evt in $DbgEvents){        $Log=New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $evt        $Log.IsEnabled =$false        $Log.SaveChanges()        $Log.IsEnabled =$true        $Log.SaveChanges()    }}

Function DisableDebugEvents ($DbgEvents){    ForEach ($evt in $DbgEvents){	    $Log = New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $evt		$Log.IsEnabled = $false		$Log.SaveChanges()    }
}

Function CollectLogAADExt($RunLogs){
    Push-Location $global:LogsPath    ForEach ($RunLog in $RunLogs){		cmd.exe /c $RunLog    }
    Pop-Location
}

Function CollectLog($RunLogs){
    Push-Location $global:LogsPath    ForEach ($RunLog in $RunLogs){		powershell.exe $RunLog    }
    Pop-Location
}

Function CompressLogsFolder{    $CompressedFile = "DSRegTool_Logs_" + (Get-Date -Format yyyy-dd-MM_hh-mm)    $FolderContent = "$(Join-Path -Path $pwd.Path -ChildPath $CompressedFile).zip"    Add-Type -Assembly "System.IO.Compression.FileSystem"    [System.IO.Compression.ZipFile]::CreateFromDirectory($global:LogsPath, $FolderContent)
    Write-host "Compressed file is ready in $FolderContent" -ForegroundColor Yellow
    # Cleanup the Temporary Folder (if error retain the temp files)
    if(Test-Path -Path $pwd.Path){
		Remove-Item -Path $global:LogsPath -Force -Recurse | Out-Null
    }else{		Write-host "The Archive could not be created. Keeping Temporary Folder $global:LogsPath"		New-Item -ItemType directory -Path $pwd.Path -Force | Out-Null    }
}

Function LogmanStart($Trace,$Providers){
    logman create trace $Trace -ow -o $global:LogsPath\$Trace.etl -nb 16 16 -bs 4096 -mode circular -f bincirc -max 1024 -ets | Out-Null

    foreach ($provider in $Providers){
        $ProviderInfo = $provider.split(",")
        logman update trace $Trace -p $ProviderInfo[0] $ProviderInfo[1] $ProviderInfo[2] -ets | Out-Null
    }
    
}

Function LogmanStop($Trace){
    logman stop $Trace -ets  | Out-Null
}

Function StartLogCollection{
    $WebAuth='{2A3C6602-411E-4DC6-B138-EA19D64F5BBA},0xFFFF,0xff',`
    '{EF98103D-8D3A-4BEF-9DF2-2156563E64FA},0xFFFF,0xff',`
    '{FB6A424F-B5D6-4329-B9B5-A975B3A93EAD},0x000003FF,0xff',`
    '{D93FE84A-795E-4608-80EC-CE29A96C8658},0x7FFFFFFF,0xff',`
    '{3F8B9EF5-BBD2-4C81-B6C9-DA3CDB72D3C5},0x7,0xff',`
    '{B1108F75-3252-4b66-9239-80FD47E06494},0x2FF,0xff',`
    '{C10B942D-AE1B-4786-BC66-052E5B4BE40E},0x3FF,0xff',`
    '{82c7d3df-434d-44fc-a7cc-453a8075144e},0x2FF,0xff',`
    '{05f02597-fe85-4e67-8542-69567ab8fd4f},0xFFFFFFFF,0xff',`
    '{3C49678C-14AE-47FD-9D3A-4FEF5D796DB9},0xFFFFFFFF,0xff',`
    '{077b8c4a-e425-578d-f1ac-6fdf1220ff68},0xFFFFFFFF,0xff',`
    '{7acf487e-104b-533e-f68a-a7e9b0431edb},0xFFFFFFFF,0xff',`
    '{5836994d-a677-53e7-1389-588ad1420cc5},0xFFFFFFFF,0xff',`
    '{4DE9BC9C-B27A-43C9-8994-0915F1A5E24F},0xFFFFFFFF,0xff',`
    '{bfed9100-35d7-45d4-bfea-6c1d341d4c6b},0xFFFFFFFF,0xff',`
    '{9EBB3B15-B094-41B1-A3B8-0F141B06BADD},0xFFF,0xff',`
    '{6ae51639-98eb-4c04-9b88-9b313abe700f},0xFFFFFFFF,0xff',`
    '{7B79E9B1-DB01-465C-AC8E-97BA9714BDA2},0xFFFFFFFF,0xff',`
    '{86510A0A-FDF4-44FC-B42F-50DD7D77D10D},0xFFFFFFFF,0xff',`
    '{08B15CE7-C9FF-5E64-0D16-66589573C50F},0xFFFFFF7F,0xff',`
    '{63b6c2d2-0440-44de-a674-aa51a251b123},0xFFFFFFFF,0xff',`
    '{4180c4f7-e238-5519-338f-ec214f0b49aa},0xFFFFFFFF,0xff',`
    '{EB65A492-86C0-406A-BACE-9912D595BD69},0xFFFFFFFF,0xff',`
    '{d49918cf-9489-4bf1-9d7b-014d864cf71f},0xFFFFFFFF,0xff',`
    '{5AF52B0D-E633-4ead-828A-4B85B8DAAC2B},0xFFFF,0xff',`
    '{2A6FAF47-5449-4805-89A3-A504F3E221A6},0xFFFF,0xff',`
    '{EC3CA551-21E9-47D0-9742-1195429831BB},0xFFFFFFFF,0xff',`
    '{bb8dd8e5-3650-5ca7-4fea-46f75f152414},0xFFFFFFFF,0xff',`
    '{7fad10b2-2f44-5bb2-1fd5-65d92f9c7290},0xFFFFFFFF,0xff',`
    '{74D91EC4-4680-40D2-A213-45E2D2B95F50},0xFFFFFFFF,0xff',`
    '{556045FD-58C5-4A97-9881-B121F68B79C5},0xFFFFFFFF,0xff',`
    '{5A9ED43F-5126-4596-9034-1DCFEF15CD11},0xFFFFFFFF,0xff',`
    '{F7C77B8D-3E3D-4AA5-A7C5-1DB8B20BD7F0},0xFFFFFFFF,0xff',`
    '{2745a526-23f5-4ef1-b1eb-db8932d43330},0xffffffffffffffff,0xff',`
    '{d48533a7-98e4-566d-4956-12474e32a680},0xffffffffffffffff,0xff',`
    '{072665fb-8953-5a85-931d-d06aeab3d109},0xffffffffffffffff,0xff',`
    '{EF00584A-2655-462C-BC24-E7DE630E7FBF},0xffffffffffffffff,0xff',`
    '{c632d944-dddb-599f-a131-baf37bf22ef0},0xffffffffffffffff,0xff'    $LSA='{D0B639E0-E650-4D1D-8F39-1580ADE72784},0xC43EFF,0xff',`
    '{169EC169-5B77-4A3E-9DB6-441799D5CACB},0xffffff,0xff',`
    '{DAA76F6A-2D11-4399-A646-1D62B7380F15},0xffffff,0xff',`
    '{366B218A-A5AA-4096-8131-0BDAFCC90E93},0xfffffff,0xff',`
    '{4D9DFB91-4337-465A-A8B5-05A27D930D48},0xff,0xff',`
    '{7FDD167C-79E5-4403-8C84-B7C0BB9923A1},0xFFF,0xff',`
    '{CA030134-54CD-4130-9177-DAE76A3C5791},0xfffffff,0xff',`
    '{5a5e5c0d-0be0-4f99-b57e-9b368dd2c76e},0xffffffffffffffff,0xff',`
    '{2D45EC97-EF01-4D4F-B9ED-EE3F4D3C11F3},0xffffffffffffffff,0xff',`
    '{C00D6865-9D89-47F1-8ACB-7777D43AC2B9},0xffffffffffffffff,0xff',`
    '{7C9FCA9A-EBF7-43FA-A10A-9E2BD242EDE6},0xffffffffffffffff,0xff',`
    '{794FE30E-A052-4B53-8E29-C49EF3FC8CBE},0xffffffffffffffff,0xff',`
    '{ba634d53-0db8-55c4-d406-5c57a9dd0264},0xffffffffffffffff,0xff'    $Ntlm_CredSSP='{5BBB6C18-AA45-49b1-A15F-085F7ED0AA90},0x5ffDf,0xff',`
    '{AC43300D-5FCC-4800-8E99-1BD3F85F0320},0xffffffffffffffff,0xff',`
    '{6165F3E2-AE38-45D4-9B23-6B4818758BD9},0xffffffff,0xff',`
    '{DAA6CAF5-6678-43f8-A6FE-B40EE096E06E},0xffffffffffffffff,0xff',`
    '{AC69AE5B-5B21-405F-8266-4424944A43E9},0xffffffff,0xff'    $Kerberos='{97A38277-13C0-4394-A0B2-2A70B465D64F},0xff,0xff',`
    '{FACB33C4-4513-4C38-AD1E-57C1F6828FC0},0xffffffff,0xff',`
    '{8a4fc74e-b158-4fc1-a266-f7670c6aa75d},0xffffffffffffffff,0xff',`
    '{60A7AB7A-BC57-43E9-B78A-A1D516577AE3},0xffffff,0xff',`
    '{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1},0xffffffffffffffff,0xff',`
    '{6B510852-3583-4e2d-AFFE-A67F9F223438},0x7ffffff,0xff'    ''
    Write-Host "Testing if script running with elevated privileges..." -ForegroundColor Yellow 
    if (PSasAdmin){
        # PS running as admin.
        Write-Host "PowerShell is running with elevated privileges" -ForegroundColor Green -BackgroundColor Black
        ''
    }else{
        Write-Host "PowerShell is NOT running with elevated privileges" -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: Log collection should to be running with elevated privileges" -ForegroundColor Yellow -BackgroundColor Black
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit
    }


    #Create DSRegToolLogs folder.
    Write-Host "Creating DSRegToolLogs folder under $pwd" -ForegroundColor Yellow
    if (!(Test-Path $global:LogsPath)){
        New-Item -itemType Directory -Path $global:LogsPath -Force | Out-Null
    }else{
        Remove-Item -Path $global:LogsPath -Force -Recurse | Out-Null
        New-Item -itemType Directory -Path $global:LogsPath -Force | Out-Null
    }

    #Create PreTrace in DSRegToolLogs folder.
    Write-Host "Checking PreTrace folder under $pwd\DSRegToolLogs" -ForegroundColor Yellow
    $global:PreTrace=$pwd.Path+"\DSRegToolLogs\PreTrace"
    if (!(Test-Path $global:PreTrace)){
        New-Item -itemType Directory -Path $global:PreTrace -Force | Out-Null
    }

    #PreTrace
    Write-Host "Collecting PreTrace logs..." -ForegroundColor Yellow
    ExportEventViewerLogs $global:PreTraceEvents $global:PreTrace
    dsregcmd /status | Out-file "$global:PreTrace\dsregcmd-status.txt"    RunPScript -PSScript "dsregcmd /status /debug" | Out-file "$global:PreTrace\dsregcmd-debug.txt"    #Press ENTER to start log collection:    ''    Write-Host "Please press ENTER to start log collection..." -ForegroundColor Green -NoNewline    Read-Host    Write-Host "Starting log collection..." -ForegroundColor Yellow    #Enable debug and network logs:    Write-Host "Enabling debug logs..." -ForegroundColor Yellow    EnableDebugEvents $global:DebugLogs    Write-Host "Starting network traces..." -ForegroundColor Yellow    LogmanStart "WebAuth" $WebAuth    LogmanStart "LSA" $LSA    LogmanStart "Ntlm_CredSSP" $Ntlm_CredSSP    LogmanStart "Kerberos" $Kerberos    $Reg=Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions -ErrorAction SilentlyContinue
    if ($Reg.ProductType -eq "WinNT"){
        netsh trace start InternetClient persistent=yes traceFile=.\DSRegToolLogs\Netmon.etl capture=yes maxsize=1024| Out-Null
    }else{
        netsh trace start persistent=yes traceFile=.\DSRegToolLogs\Netmon.etl capture=yes maxsize=1024| Out-Null
    }
    ''    ''    Write-Host "Log collection has started, please start repro the issue..." -ForegroundColor Yellow    ''}Function StopLogCollection{    Write-Host "When repro finished, please press ENTER to stop log collection..." -ForegroundColor Green -NoNewline    Read-Host     #Disable debug and analytic logs:    DisableDebugEvents $global:DebugLogs    #Collect logs    Write-Host "Log collection has been stopped, please wait until we gather all files..." -ForegroundColor Yellow    Write-Host "Exporting event viewer logs..." -ForegroundColor Yellow    ExportEventViewerLogs $global:Events $global:LogsPath    Write-Host "Exporting files..." -ForegroundColor Yellow    CollectLog $global:CopyFiles    Write-Host "Exporting registry keys..." -ForegroundColor Yellow    RunPScript -PSScript "dsregcmd /status /debug" | Out-file "$global:LogsPath\dsregcmd-debug.txt"    Test-DevRegConnectivity $false | Out-file "$global:LogsPath\TestDeviceRegConnectivity.txt"    CollectLog $global:RegKeys    CollectLogAADExt $global:AADExt    Write-Host "Stopping network traces..." -ForegroundColor Yellow    LogmanStop "WebAuth"    LogmanStop "LSA"    LogmanStop "Ntlm_CredSSP"    LogmanStop "Kerberos"    netsh trace stop | Out-Null    Write-Host "Compressing collected logs..." -ForegroundColor Yellow    CompressLogsFolder
    ''
    ''
    Write-Host "Log collection completed successfully" -ForegroundColor Green -NoNewline
    ''
    ''
}

Function LogsCollection{
    $global:LogsPath=$pwd.Path+"\DSRegToolLogs"
    $global:PreTraceEvents = "Microsoft-Windows-AAD/Operational","Microsoft-Windows-User Device Registration/Admin","Microsoft-Windows-CAPI2/Operational","Microsoft-Windows-HelloForBusiness/Operational","Microsoft-Windows-LiveId/Operational","Microsoft-Windows-User Control Panel/Operational","Microsoft-Windows-WebAuth/Operational","Microsoft-Windows-WebAuthN/Operational","Microsoft-Windows-Biometrics/Operational","Microsoft-Windows-IdCtrls/Operational","Microsoft-Windows-Crypto-DPAPI/Operational"
    $global:DebugLogs="Microsoft-Windows-AAD/Analytic","Microsoft-Windows-User Device Registration/Debug"
    $global:Events = $global:PreTraceEvents + "Microsoft-Windows-AAD/Analytic","Microsoft-Windows-User Device Registration/Debug","System","Application","Microsoft-Windows-Shell-Core/Operational","Microsoft-Windows-Kerberos/Operational","Microsoft-Windows-CertPoleEng/Operational","Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController","Microsoft-Windows-Authentication/ProtectedUser-Client","Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController","Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController","Microsoft-Windows-WMI-Activity/Operational","Microsoft-Windows-GroupPolicy/Operational"

    $global:CopyFiles='if (Test-Path "$env:windir\debug\netlogon.log"){Copy-Item "$env:windir\debug\netlogon.log" -Destination "netlogon.log" | Out-Null}',`
    'if (Test-Path "$env:windir\system32\drivers\etc\hosts"){Copy-Item "$env:windir\system32\drivers\etc\hosts" -Destination "hosts.txt" | Out-Null}',`
    'if (Test-Path "$env:windir\debug\Netsetup.log"){Copy-Item "$env:windir\debug\Netsetup.log" -Destination "Netsetup.log" | Out-Null}',`
    'if (Test-Path "$env:windir\system32\Lsass.log"){Copy-Item "$env:windir\system32\Lsass.log" -Destination "Lsass.log" | Out-Null}'

    $global:RegKeys = 'ipconfig /all > ipconfig-all.txt',`
    'dsregcmd /status > dsregcmd-status.txt',`
    '[environment]::OSVersion | fl * > Winver.txt',`
    'netstat -nao > netstat-nao.txt',`
    'route print > route-print.txt',`
    'net start > services-running.txt',`
    'tasklist > tasklist.txt',`
    'netsh winhttp show proxy > netsh-winhttp-proxy.txt',`
    'wmic qfe list full /format:htable > Patches.htm',`
    'GPResult /f /h GPResult.html',`
    'regedit /e CloudDomainJoin.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CloudDomainJoin',`
    'regedit /e Lsa.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa',`
    'regedit /e Netlogon.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon',`
    'regedit /e Schannel.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL',`
    'regedit /e Winlogon.txt HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',`
    'regedit /e Winlogon-current-control-set.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Winlogon',`
    'regedit /e IdentityStore.txt HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityStore',`
    'regedit /e WorkplaceJoin-windows.txt HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin',`
    'regedit /e WorkplaceJoin-control.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WorkplaceJoin',`
    'regedit /e SCP-client-side.txt HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD',`
    'regedit /e WPJ-info.txt HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AAD'

    $global:AADExt='set > set.txt',`
    'sc query  > services-config.txt',`    'md AADExtention',`    'curl -H Metadata:true http://169.254.169.254/metadata/identity/info?api-version=2018-02-01 > .\AADExtention\metadata.txt 2>&0',`    'curl https://login.microsoftonline.com/ -D - > .\AADExtention\login.microsoftonline.com.txt 2>&0',`    'curl https://enterpriseregistration.windows.net/ -D - > .\AADExtention\enterpriseregistration.windows.net.txt 2>&0',`    'curl https://device.login.microsoftonline.com/ -D - > .\AADExtention\device.login.microsoftonline.com.txt 2>&0',`    'curl https://pas.windows.net/ -D - > .\AADExtention\pas.windows.net.txt 2>&0',`    'xcopy C:\WindowsAzure\Logs\Plugins\Microsoft.Azure.ActiveDirectory.AADLoginForWindows .\AADExtention\Microsoft.Azure.ActiveDirectory.AADLoginForWindows /E /H /C /I 2>&0 > null'
    If ((((New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration "Microsoft-Windows-AAD/Analytic").IsEnabled) -and ((New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration "Microsoft-Windows-User Device Registration/Debug").IsEnabled))){        write-Host "Debug logs are enabled, it seems you started log collection." -ForegroundColor Yellow        write-Host "Do you want to continue with current log collection? [Y/N]" -ForegroundColor Yellow        $input=Read-Host "Enter 'Y' to continue, or 'N' to start a new log collection"        While(($input -ne 'y') -AND ($input -ne 'n')){
            $input = Read-Host -Prompt "Invalid input. Please make a correct selection from the above options, and press Enter" 
        }        if($input -eq 'y'){            #Test if DSRegToolLog folder exist            if(Test-Path $global:LogsPath){                #Stop log collection, when repro finished, please press ENTER.                StopLogCollection            }else{                Write-Host "Please locate DSRegToolLog folder/path where you start the tool previously, and start the tool again."            }        }elseif($input -eq 'n'){            #Start log collection from bigning            StartLogCollection            StopLogCollection        }    }else{        #Start log collection from bigning        StartLogCollection        StopLogCollection    }
}
#Eng of Log Collection functions

Function CheckInternet
{
$statuscode = (Invoke-WebRequest -Uri https://adminwebservice.microsoftonline.com/ProvisioningService.svc -UseBasicParsing).statuscode
if ($statuscode -ne 200){
''
''
Write-Host "Operation aborted. Unable to connect to Azure AD, please check your internet connection." -ForegroundColor red -BackgroundColor Black
exit
}
}

Function CheckMSOnline{
''
Write-Host "Checking MSOnline Module..." -ForegroundColor Yellow
                            
    if (Get-Module -ListAvailable -Name MSOnline) {
        Import-Module MSOnline
        Write-Host "MSOnline Module has imported." -ForegroundColor Green -BackgroundColor Black
        ''
        Write-Host "Connecting to MSOnline..." -ForegroundColor Yellow
        
        if ($SavedCreds){
            Connect-MsolService -Credential $UserCreds -ErrorAction SilentlyContinue
        }else{
            Connect-MsolService -ErrorAction SilentlyContinue
        }

        if (-not (Get-MsolCompanyInformation -ErrorAction SilentlyContinue)){
            Write-Host "Operation aborted. Unable to connect to MSOnline, please check you entered a correct credentials and you have the needed permissions." -ForegroundColor red -BackgroundColor Black
            exit
        }
        Write-Host "Connected to MSOnline successfully." -ForegroundColor Green -BackgroundColor Black
        ''
    } else {
        Write-Host "MSOnline Module is not installed." -ForegroundColor Red -BackgroundColor Black
        Write-Host "Installing MSOnline Module....." -ForegroundColor Yellow
        CheckInternet
        Install-Module MSOnline -force
                                
        if (Get-Module -ListAvailable -Name MSOnline) {                                
        Write-Host "MSOnline Module has installed." -ForegroundColor Green -BackgroundColor Black
        Import-Module MSOnline
        Write-Host "MSOnline Module has imported." -ForegroundColor Green -BackgroundColor Black
        ''
        Write-Host "Connecting to MSOnline..." -ForegroundColor Yellow
        Connect-MsolService -ErrorAction SilentlyContinue
        
        if (-not (Get-MsolCompanyInformation -ErrorAction SilentlyContinue)){
            Write-Host "Operation aborted. Unable to connect to MSOnline, please check you entered a correct credentials and you have the needed permissions." -ForegroundColor red -BackgroundColor Black
            exit
        }
        Write-Host "Connected to MSOnline successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        } else {
        ''
        ''
        Write-Host "Operation aborted. MsOnline was not installed." -ForegroundColor red -BackgroundColor Black
        exit
        }
    }



}

Function RunPScript([String] $PSScript){

$GUID=[guid]::NewGuid().Guid

$Job = Register-ScheduledJob -Name $GUID -ScheduledJobOption (New-ScheduledJobOption -RunElevated) -ScriptBlock ([ScriptBlock]::Create($PSScript)) -ArgumentList ($PSScript) -ErrorAction Stop

$Task = Register-ScheduledTask -TaskName $GUID -Action (New-ScheduledTaskAction -Execute $Job.PSExecutionPath -Argument $Job.PSExecutionArgs) -Principal (New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest) -ErrorAction Stop

$Task | Start-ScheduledTask -AsJob -ErrorAction Stop | Wait-Job | Remove-Job -Force -Confirm:$False

While (($Task | Get-ScheduledTaskInfo).LastTaskResult -eq 267009) {Start-Sleep -Milliseconds 150}

$Job1 = Get-Job -Name $GUID -ErrorAction SilentlyContinue | Wait-Job
$Job1 | Receive-Job -Wait -AutoRemoveJob 

Unregister-ScheduledJob -Id $Job.Id -Force -Confirm:$False

Unregister-ScheduledTask -TaskName $GUID -Confirm:$false
}

Function CheckCert ([String] $DeviceID, [String] $DeviceThumbprint){

    #Search for the certificate:
    if ($localCert = dir Cert:\LocalMachine\My\ | where { $_.Issuer -match "CN=MS-Organization-Access" -and $_.Subject -match "CN="+$DeviceID}){
    #The certificate exists
    Write-Host "Certificate does exist." -ForegroundColor Green
    #Cheching the certificate configuration

        $CertSubject = $localCert.subject
        $CertDNSNameList = $localCert.DnsNameList
        $CertThumbprint = $localCert.Thumbprint
        $NotBefore = $localCert.NotBefore
        $NotAfter = $localCert.NotAfter
        $IssuerName = $localCert.IssuerName
        $Issuer = $localCert.Issuer
        $subbectName = $localCert.SubjectName
        $Algorithm = $localCert.SignatureAlgorithm
        $PublicKey = $localCert.PublicKey
        $HasPrivateKey = $localCert.HasPrivateKey



        # Check Cert Expiration
        if (($NotAfter.toString("yyyy-M-dd")) -gt (Get-Date -format yyyy-M-dd)){
            Write-Host "Certificate is not expired." -ForegroundColor Green
        }else{
            Write-Host "The certificate has expired." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
            
        }


        # Check DeviceID and CertSubject
        $CertDNSName = $CertDNSNameList | select Punycode,Unicode

        if (($DeviceID -ne $CertDNSName.Punycode) -or ($DeviceID -ne $CertDNSName.Unicode)){
            Write-Host "The certificate subject is not correct." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate subject is correct." -ForegroundColor Green
        }



        # Check IssuerName
        if (($IssuerName.Name -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97") -or ($Issuer -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97")){
            Write-Host "Certificate Issuer is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate issuer is correct." -ForegroundColor Green
        }


        # Check AlgorithmFriendlyName
        if ($Algorithm.FriendlyName -ne "sha256RSA"){
            Write-Host "Certificate Algorithm is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate Algorithm is correct." -ForegroundColor Green
        }


        # Check AlgorithmFValue
        if ($Algorithm.Value -ne "1.2.840.113549.1.1.11"){
            Write-Host "Certificate Algorithm Value is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate Algorithm Value is correct." -ForegroundColor Green
        }
        

        # Check PrivateKey
        if ($HasPrivateKey -ne "True"){
            Write-Host "Certificate PrivateKey does not exist." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate PrivateKey is correct." -ForegroundColor Green
        }



    
    }else{
    #Certificate does not exist.
    Write-Host "Device certificate does not exist." -ForegroundColor Red
    ''
    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

    }
    

}#End of function

Function CheckUserCert ([String] $DeviceID, [String] $DeviceThumbprint){

    #Search for the certificate:
    if ($localCert = dir Cert:\CurrentUser\My\ | where { $_.Issuer -match "CN=MS-Organization-Access" -and $_.Subject -match "CN="+$DeviceID}){
    #The certificate exists
    Write-Host "Certificate does exist." -ForegroundColor Green
    #Cheching the certificate configuration

        $CertSubject = $localCert.subject
        $CertDNSNameList = $localCert.DnsNameList
        $CertThumbprint = $localCert.Thumbprint
        $NotBefore = $localCert.NotBefore
        $NotAfter = $localCert.NotAfter
        $IssuerName = $localCert.IssuerName
        $Issuer = $localCert.Issuer
        $subbectName = $localCert.SubjectName
        $Algorithm = $localCert.SignatureAlgorithm
        $PublicKey = $localCert.PublicKey
        $HasPrivateKey = $localCert.HasPrivateKey



        # Check Cert Expiration
        if (($NotAfter.toString("yyyy-M-dd")) -gt (Get-Date -format yyyy-M-dd)){
            Write-Host "Certificate is not expired." -ForegroundColor Green
        }else{
            Write-Host "The certificate has expired." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
            
        }


        # Check DeviceID and CertSubject
        $CertDNSName = $CertDNSNameList | select Punycode,Unicode

        if (($DeviceID -ne $CertDNSName.Punycode) -or ($DeviceID -ne $CertDNSName.Unicode)){
            Write-Host "The certificate subject is not correct." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate subject is correct." -ForegroundColor Green
        }



        # Check IssuerName
        if (($IssuerName.Name -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97") -or ($Issuer -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97")){
            Write-Host "Certificate Issuer is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate issuer is correct." -ForegroundColor Green
        }


        # Check AlgorithmFriendlyName
        if ($Algorithm.FriendlyName -ne "sha256RSA"){
            Write-Host "Certificate Algorithm is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate Algorithm is correct." -ForegroundColor Green
        }


        # Check AlgorithmFValue
        if ($Algorithm.Value -ne "1.2.840.113549.1.1.11"){
            Write-Host "Certificate Algorithm Value is not configured correctly." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate Algorithm Value is correct." -ForegroundColor Green
        }
        

        # Check PrivateKey
        if ($HasPrivateKey -ne "True"){
            Write-Host "Certificate PrivateKey does not exist." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            Write-Host "Certificate PrivateKey is correct." -ForegroundColor Green
        }



    
    }else{
    #Certificate does not exist.
    Write-Host "Device certificate does not exist." -ForegroundColor Red
    ''
    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

    }
    

}#End of function

Function NewFun{

                #The device is hybrid Azure AD join
                $TenantName = $DSReg | Select-String TenantName | Select-Object -first 1
                $TenantName =($TenantName.tostring() -split ":")[1].trim()
                $hostname = hostname
                Write-Host $hostname "device is joined to Azure AD tenant that has the name of" $TenantName -ForegroundColor Green
        
                ''
                Write-Host "Checking Key provider..." -ForegroundColor Yellow
                #Checking the KeyProvider:
                $KeyProvider = $DSReg | Select-String KeyProvider | Select-Object -first 1
                $KeyProvider = ($KeyProvider.tostring() -split ":")[1].trim()
                if (($KeyProvider -ne "Microsoft Platform Crypto Provider") -and ($KeyProvider -ne "Microsoft Software Key Storage Provider")){
                    Write-Host "The KeyProvider is not configured correctly." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

                }else{
                    Write-Host "Certificate key provider configured correctly." -ForegroundColor Green
                }

                # Check other values.

                #Checking the certificate:
                $DID = $DSReg | Select-String DeviceId | Select-Object -first 1
                $DID = ($DID.ToString() -split ":")[1].Trim()
        

                $DTP = $DSReg | Select-String Thumbprint | Select-Object -first 1
                $DTP = ($DTP.ToString() -split ":")[1].Trim()
        
                ''
                Write-Host "Checking the device certificate configuration..." -ForegroundColor Yellow
                CheckCert -DeviceID $DID -DeviceThumbprint $DTP


        ''
        Write-Host "Checking the device status on Azure AD..." -ForegroundColor Yellow

        CheckMSOnline

        #Check the device status on AAD:
        $AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
        #Check if the device exist:
        ''
        Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
        if ($AADDevice.count -ge 1){
            #The device existing in AAD:
            Write-Host "The device object exists on Azure AD." -ForegroundColor Green
            #Check if the device is enabled:
            ''
            Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
                if ($AADDevice.Enabled -eq $false){
                    Write-Host "The device is not enabled on Azure AD tenant." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

            }else{
                    Write-Host "The device is enabled on Azure AD tenant." -ForegroundColor Green
            }

            #Check if the device is registered (not Pending):
            ''
            Write-Host "Checking device PENDING state..." -ForegroundColor Yellow
            [string]$AltSec=$AADDevice.AlternativeSecurityIds
            if (-not ($AltSec.StartsWith("X509:"))){
                Write-Host "Test failed: the device in 'Pending' state on Azure AD." -ForegroundColor Red
                ''
                Write-Host "Recommended actions: Device registration process will not trigger as the device feels itself as a registered device. To fix this issue, do the following:" -ForegroundColor Yellow
                Write-Host "                     - Clear the device state by running the command 'dsregcmd /leave' as admin. " -ForegroundColor Yellow
                Write-Host "                     - Run 'dsregcmd /join' command as admin to perform hybrid Azure AD join procedure and rerun the script." -ForegroundColor Yellow
                Write-Host "                       If the issue still persists, check the possible courses on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit

            }else{
                    Write-Host "The device is not in PENDING state." -ForegroundColor Green
            }


                #get ApproximateLastLogonTimestamp value
                $global:LastLogonTimestamp = $AADDevice.ApproximateLastLogonTimestamp
                

        }else{
            #Device does not exist:
            Write-Host "The device does not exist in your Azure AD tenant." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again. If you have a Managed domain, make sure the device is in the sync scope." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }

        ''
        Write-Host "Checking dual state..." -ForegroundColor Yellow
        $HAADJTID = $DSReg | Select-String TenantId | Select-Object -first 1
        $WPJTID = $DSReg | Select-String WorkplaceTenantId | Select-Object -first 1
        $WPJ = $DSReg | Select-String WorkplaceJoined
        $WPJ = ($WPJ.tostring() -split ":")[1].trim()
        if (($WPJ -eq "YES") -and ($HAADJTID -eq $WPJTID)){
            Write-Host "The device in dual state." -ForegroundColor Red
            ''
            Write-Host "Recommended action: upgrade your OS to Windows 10 1803 (with KB4489894 applied). In pre-1803 releases, you will need to remove the Azure AD registered state manually before enabling Hybrid Azure AD join by disconnecting the user from Access Work or School Account." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
        }elseif ($WPJ -ne "YES"){
            #Check if there is atoken inside the path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com
            if ((Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com -ErrorAction SilentlyContinue).PSPath){
                Write-Host "The device in dual state." -ForegroundColor Red
                ''
                Write-Host "Recommended action: remove the registry key 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\'" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit                
            }
        }else{
                Write-Host "The device is not in dual state." -ForegroundColor Green
        }



    ''
    ''
    Write-Host "The device is connected to AAD as hybrid Azure AD joined device, and it is in healthty state." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''      
}

Function NewFunAAD{

                #The device is Azure AD joined
                $TenantName = $DSReg | Select-String TenantName | Select-Object -first 1
                $TenantName =($TenantName.tostring() -split ":")[1].trim()
                $hostname = hostname
                Write-Host $hostname "device is joined to Azure AD tenant that has the name of" $TenantName -ForegroundColor Green
        
                ''
                Write-Host "Checking Key provider..." -ForegroundColor Yellow
                #Checking the KeyProvider:
                $KeyProvider = $DSReg | Select-String KeyProvider
                $KeyProvider = ($KeyProvider.tostring() -split ":")[1].trim()
                if (($KeyProvider -ne "Microsoft Platform Crypto Provider") -and ($KeyProvider -ne "Microsoft Software Key Storage Provider")){
                    Write-Host "The KeyProvider is not configured correctly." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

                }else{
                    Write-Host "Certificate key provider configured correctly." -ForegroundColor Green
                }

                # Check other values.

                #Checking the certificate:
                $DID = $DSReg | Select-String DeviceId
                $DID = ($DID.ToString() -split ":")[1].Trim()
        

                $DTP = $DSReg | Select-String Thumbprint
                $DTP = ($DTP.ToString() -split ":")[1].Trim()
        
                ''
                Write-Host "Checking the device certificate configuration..." -ForegroundColor Yellow
                CheckCert -DeviceID $DID -DeviceThumbprint $DTP


        ''
        Write-Host "Checking the device status on Azure AD..." -ForegroundColor Yellow

        CheckMSOnline

        #Check the device status on AAD:
        $AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
        #Check if the device exist:
        ''
        Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
        if ($AADDevice.count -ge 1){
            #The device existing in AAD:
            ''
            Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
            #Check if the device is enabled:
            ''
            Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
                if ($AADDevice.Enabled -eq $false){
                    Write-Host "The device is not enabled on Azure AD tenant." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

            }else{
                    Write-Host "The device is enabled on Azure AD tenant." -ForegroundColor Green
            }


                #get ApproximateLastLogonTimestamp value
                $global:LastLogonTimestamp = $AADDevice.ApproximateLastLogonTimestamp
                

        }else{
            #Device does not exist:
            Write-Host "The device does not exist in your Azure AD tenant." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Disconnect the device from Azure AD form 'settings > Accounts > Access work or school' and then connect it again to AAD." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit


        }

    ''
    ''
    Write-Host "The device is connected successfully to AAD as Azure AD joined device, and it is in healthty state." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''        
}

Function NewFunWPJ{

                #The device is Azure AD joined
                $TenantName = $DSReg | Select-String WorkplaceTenantName 
                $TenantName =($TenantName.tostring() -split ":")[1].trim()
                $hostname = hostname
                Write-Host $hostname "device is connected to Azure AD tenant that has the name of" $TenantName "as Azure AD Register device" -ForegroundColor Green

                # Check other values.

                #Checking the certificate:
                $DID = $DSReg | Select-String WorkplaceDeviceId
                $DID = ($DID.ToString() -split ":")[1].Trim()
        

                $DTP = $DSReg | Select-String WorkplaceThumbprint
                $DTP = ($DTP.ToString() -split ":")[1].Trim()
        
                ''
                Write-Host "Checking the device certificate configuration..." -ForegroundColor Yellow
                CheckUserCert -DeviceID $DID -DeviceThumbprint $DTP


        ''
        Write-Host "Checking the device status on Azure AD..." -ForegroundColor Yellow

        CheckMSOnline

        #Check the device status on AAD:
        $AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
        #Check if the device exist:
        ''
        Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
        if ($AADDevice.count -ge 1){
            #The device existing in AAD:
            Write-Host "The device object exist on Azure AD." -ForegroundColor Green
            #Check if the device is enabled:
            ''
            Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
                if ($AADDevice.Enabled -eq $false){
                    Write-Host "The device is not enabled on Azure AD tenant." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

            }else{
                    Write-Host "The device is enabled on Azure AD tenant." -ForegroundColor Green
            }


                #get ApproximateLastLogonTimestamp value
                $global:LastLogonTimestamp = $AADDevice.ApproximateLastLogonTimestamp
                

        }else{
            #Device does not exist:
            Write-Host "The device does not exist in your Azure AD tenant." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Disconnect the device from Azure AD form 'settings > Accounts > Access work or school' and then connect it again to AAD." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit


        }

    ''
    ''
    Write-Host "The device is connected successfully to AAD as Azure AD registered device, and it is in healthty state." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''        
}

Function DJ++1{
        #Check OS version:
        ''
        Write-Host "Checking OS version..." -ForegroundColor Yellow
        $OSVersoin = ([environment]::OSVersion.Version).major
        if ($OSVersoin -ge 10){
        Write-Host "Device has current OS version." -ForegroundColor Green
        #Check dsregcmd status.
        $DSReg = dsregcmd /status

        ''
        Write-Host "Checking if the device joined to the local domain..." -ForegroundColor Yellow
        $DJ = $DSReg | Select-String DomainJoin
        $DJ = ($DJ.tostring() -split ":")[1].trim()
        if ($DJ -ne "YES"){
            $hostname = hostname
            Write-Host $hostname "device is NOT joined to the local domain" -ForegroundColor Red
            ''
            Write-Host "Recommended action: You need to join the device to the local domain in order to perform hybrid Azure AD join." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

        }else{
            #The device is joined to the local domain.
            $DomainName = $DSReg | Select-String DomainName 
            $DomainName =($DomainName.tostring() -split ":")[1].trim()
            $hostname = hostname
            Write-Host $hostname "device is joined to the local domain that has the name of" $DomainName -ForegroundColor Green
    
            #Checking if the device connected to AzureAD
            ''
            Write-Host "Checking if the device is connected to AzureAD..." -ForegroundColor Yellow
            $AADJ = $DSReg | Select-String AzureAdJoined
            $AADJ = ($AADJ.tostring() -split ":")[1].trim()
            if ($AADJ -ne "YES"){
            #The device is not connected to AAD:
            Write-Host $hostname "device is NOT connected to Azure AD" -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /join' command as admin to perform hybrid Azure AD join procedure and re-run the script again, if the issue still persists, check the possible courses on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

            }else{
                #The device is hybrid Azure AD join
                $TenantName = $DSReg | Select-String TenantName | Select-Object -first 1
                $TenantName =($TenantName.tostring() -split ":")[1].trim()
                $hostname = hostname
                Write-Host $hostname "device is joined to Azure AD tenant that has the name of" $TenantName -ForegroundColor Green
        
                ''
                Write-Host "Checking Key provider..." -ForegroundColor Yellow
                #Checking the KeyProvider:
                $KeyProvider = $DSReg | Select-String KeyProvider
                $KeyProvider = ($KeyProvider.tostring() -split ":")[1].trim()
                if (($KeyProvider -ne "Microsoft Platform Crypto Provider") -and ($KeyProvider -ne "Microsoft Software Key Storage Provider")){
                    Write-Host "The KeyProvider is not configured correctly." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

                }else{
                    Write-Host "Certificate key provider configured correctly." -ForegroundColor Green
                }

                # Check other values.

                #Checking the certificate:
                $DID = $DSReg | Select-String DeviceId
                $DID = ($DID.ToString() -split ":")[1].Trim()
        

                $DTP = $DSReg | Select-String Thumbprint
                $DTP = ($DTP.ToString() -split ":")[1].Trim()
        
                ''
                Write-Host "Checking the device certificate configuration..." -ForegroundColor Yellow
                CheckCert -DeviceID $DID -DeviceThumbprint $DTP


        ''
        Write-Host "Checking the device status on Azure AD..." -ForegroundColor Yellow

        CheckMSOnline

        #Check the device status on AAD:
        $AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
        #Check if the device exist:
        ''
        Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
        if ($AADDevice.count -ge 1){
            #The device existing in AAD:
            Write-Host "The device object exist on Azure AD." -ForegroundColor Green
            #Check if the device is enabled:
            ''
            Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
                if ($AADDevice.Enabled -eq $false){
                    Write-Host "The device is not enabled on Azure AD tenant." -ForegroundColor Red
                    ''
                    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
                    ''
                    ''
                    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                    ''
                    ''
                    exit

            }else{
                    Write-Host "The device is enabled on Azure AD tenant." -ForegroundColor Green
            }

            #Check if the device is registered (not Pending):
            ''
            Write-Host "Checking device PENDING state..." -ForegroundColor Yellow
            [string]$AltSec=$AADDevice.AlternativeSecurityIds
            if (-not ($AltSec.StartsWith("X509:"))){
                Write-Host "Test failed: the device in 'Pending' state on Azure AD." -ForegroundColor Red
                ''
                Write-Host "Recommended actions: Device registration process will not trigger as the device feels itself as a registered device. To fix this issue, do the following:" -ForegroundColor Yellow
                Write-Host "                     - Clear the device state by running the command 'dsregcmd /leave' as admin. " -ForegroundColor Yellow
                Write-Host "                     - Run 'dsregcmd /join' command as admin to perform hybrid Azure AD join procedure and rerun the script." -ForegroundColor Yellow
                Write-Host "                       If the issue still persists, check the possible courses on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit

            }else{
                    Write-Host "The device is not in PENDING state." -ForegroundColor Green
            }


                #get ApproximateLastLogonTimestamp value
                $global:LastLogonTimestamp = $AADDevice.ApproximateLastLogonTimestamp
                

        }else{
            #Device does not exist:
            Write-Host "The device does not exist in your Azure AD tenant." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again. If you have a Managed domain, make sure the device is in the sync scope." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit


        }

#
            }

        }

        }else{
            # dsregcmd will not work.
            Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

         
    }

    ''
    ''
    Write-Host "The device is connected to AAD as hybrid Azure AD joined device, and it is in healthty state." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
}

Function DJ++{
        #Check OS version:
        ''
        Write-Host "Checking OS version..." -ForegroundColor Yellow
        $OSVersoin = ([environment]::OSVersion.Version).major
        if ($OSVersoin -ge 10){
        Write-Host "Device has current OS version." -ForegroundColor Green
        #Check dsregcmd status.
        $DSReg = dsregcmd /status

        ''
        Write-Host "Checking if the device joined to the local domain..." -ForegroundColor Yellow
        $DJ = $DSReg | Select-String DomainJoin
        $DJ = ($DJ.tostring() -split ":")[1].trim()
        if ($DJ -ne "YES"){
            $hostname = hostname
            Write-Host $hostname "device is NOT joined to the local domain" -ForegroundColor Yellow
            ''
            Write-Host "Checking if the device joined to Azure AD..." -ForegroundColor Yellow
            $AADJ = $DSReg | Select-String AzureAdJoined
            $AADJ = ($AADJ.tostring() -split ":")[1].trim()
                if ($AADJ -ne "YES"){
                    #The device is not joined to AAD:
                    Write-Host $hostname "device is NOT joined to Azure AD." -ForegroundColor Yellow
                    ''
                    Write-Host "Checking if the device is workplace join..." -ForegroundColor Yellow
                    $WPJ = $DSReg | Select-String WorkplaceJoined
                    $WPJ = ($WPJ.tostring() -split ":")[1].trim()
                        if ($WPJ -ne "YES"){
                            #The device is not WPJ:
                            Write-Host $hostname "device is NOT Workplace Joined." -ForegroundColor Yellow
                            ''
                            Write-Host $hostname "The device is not connected to Azure AD." -BackgroundColor Black -ForegroundColor Red
                            ''
                            ''
                            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                            ''
                            ''
                            #exit
                        }else{
                            #The device is WPJ
                            NewFunWPJ
                        }

                }else{
                    #Device joined to AAD
                    NewFunAAD
                }

        }else{
            #The device is joined to the local domain.
            $DomainName = $DSReg | Select-String DomainName 
            $DomainName =($DomainName.tostring() -split ":")[1].trim()
            $hostname = hostname
            Write-Host $hostname "device is joined to the local domain that has the name of" $DomainName -ForegroundColor Green
    
            #Checking if the device connected to AzureAD
            ''
            Write-Host "Checking if the device is connected to AzureAD..." -ForegroundColor Yellow
            $AADJ = $DSReg | Select-String AzureAdJoined
            $AADJ = ($AADJ.tostring() -split ":")[1].trim()
            if ($AADJ -ne "YES"){
            #The device is not connected to AAD:
            Write-Host $hostname "device is NOT connected to Azure AD" -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run 'dsregcmd /join' command as admin to perform hybrid Azure AD join procedure. To troubleshoot hybrid device registration, re-run the tool and select option #3. If the issue still persists, check the possible courses on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

            }else{
                NewFun

            }

        }

        }else{
            # dsregcmd will not work.
            Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
            ''
            Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit

         
    }


    
}


Function DJ++TS{
$ErrorActionPreference= 'silentlycontinue'
#Check PSAdmin
''
Write-Host "Testing if PowerShell running with elevated privileges..." -ForegroundColor Yellow 
if (PSasAdmin){
    # PS running as admin.
    Write-Host "PowerShell is running with elevated privileges" -ForegroundColor Green -BackgroundColor Black
}else{
    Write-Host "PowerShell is NOT running with elevated privileges" -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: This test needs to be running with elevated privileges" -ForegroundColor Yellow -BackgroundColor Black
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}

#Check OS version:
''
Write-Host "Testing OS version..." -ForegroundColor Yellow
$OSVersoin = ([environment]::OSVersion.Version).major
$OSBuild = ([environment]::OSVersion.Version).Build
if (($OSVersoin -ge 10) -and ($OSBuild -ge 1511)){
    Write-Host "Test passed: device has current OS version." -ForegroundColor Green -BackgroundColor Black

}else{
    # dsregcmd will not work.
    Write-Host "The device has a Windows down-level OS version." -ForegroundColor Red
    ''
    Write-Host "Recommended action: Run this test on current OS versions e.g. Windows 10, Server 2016 and above." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}


#Check dsregcmd status.
$DSReg = dsregcmd /status

''
Write-Host "Testing if the device joined to the local domain..." -ForegroundColor Yellow
$DJ = $DSReg | Select-String DomainJoin
$DJ = ($DJ.tostring() -split ":")[1].trim()
if ($DJ -ne "YES"){
    $hostname = hostname
    Write-Host $hostname "Test failed: device is NOT joined to the local domain" -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: You need to join the device to the local domain in order to perform hybrid Azure AD join." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}else{
    #The device is joined to the local domain.
    $DomainName = $DSReg | Select-String DomainName 
    $DomainName =($DomainName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host "Test passed:" $hostname "device is joined to the local domain that has the name of" $DomainName -ForegroundColor Green -BackgroundColor Black
}    

#Checking if the device connected to AzureAD
''
Write-Host "Testing if the device is connected to AzureAD..." -ForegroundColor Yellow
$AADJ = $DSReg | Select-String AzureAdJoined
$AADJ = ($AADJ.tostring() -split ":")[1].trim()
if ($AADJ -ne "YES"){
    #The device is not connected to AAD:
    ### perform DJ++ (all other tests should be here)
    Write-Host "Test failed:" $hostname "device is NOT connected to Azure AD" -ForegroundColor Red -BackgroundColor Black
    #Check Automatic-Device-Join Task
    ''
    Write-Host "Testing Automatic-Device-Join task scheduler..." -ForegroundColor Yellow
    $TaskState=(Get-ScheduledTask -TaskName Automatic-Device-Join).State
    if ($TaskState -ne 'Ready'){
        Write-Host $hostname "Test failed: Automatic-Device-Join task scheduler is not ready" -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: please enable 'Automatic-Device-Join' task from 'Task Scheduler Library\Microsoft\Windows\Workplace Join'." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit
    }else{
        Write-Host "Test passed: Automatic-Device-Join task scheduler is ready" -ForegroundColor Green -BackgroundColor Black
    }

    VerifySCP

    #Check connectivity to DC if it has not performed yet
    if ($global:DCTestPerformed=$false){
        ''
        Write-Host "Testing Domain Controller connectivity..." -ForegroundColor Yellow
        $Root = [ADSI]"LDAP://RootDSE"
        $ConfigurationName = $Root.rootDomainNamingContext
        if (($ConfigurationName.length) -eq 0){
            Write-Host "Test failed: connection to Domain Controller failed" -ForegroundColor Red -BackgroundColor Black
            ''
            Write-Host "Recommended action: Make sure that the device has a line of sight to the Domain controller" -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit        
        }else{
            Write-Host "Test passed: connection to Domain Controller succeeded" -ForegroundColor Green -BackgroundColor Black
        }
    }

    #Checking Internet connectivity
    Test-DevRegConnectivity $true | Out-Null

    # If test failed
    if ($global:TestFailed){
        ''
        ''
        Write-Host "Test failed: device is not able to communicate with MS endpoints under system account" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended actions: " -ForegroundColor Yellow
        Write-Host "- Make sure that the device is able to communicate with the above MS endpoints successfully under the system account." -ForegroundColor Yellow
        Write-Host "- If the organization requires access to the internet via an outbound proxy, it is recommended to implement Web Proxy Auto-Discovery (WPAD)." -ForegroundColor Yellow
        Write-Host "- If you don't use WPAD, you can configure proxy settings with GPO by deploying WinHTTP Proxy Settings on your computers beginning with Windows 10 1709." -ForegroundColor Yellow
        Write-Host "- If the organization requires access to the internet via an authenticated outbound proxy, make sure that Windows 10 computers can successfully authenticate to the outbound proxy using the machine context." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit
    }

    ###conn

    #Testing if the device synced (with managed domain)
    ''
    Write-Host "Checking domain authenication type..." -ForegroundColor Yellow
    #Check if URL status code is 200
    #check through proxy if exist
    #run under sys account
    $UserRelmURL = "https://login.microsoftonline.com/common/UserRealm/?user=$global:TenantName&api-version=1.0"
    if ($global:ProxyServer -eq "NoProxy"){
        #$UserRealmJson= Invoke-WebRequest -uri $UserRelmURL -UseBasicParsing
        $PSScript = "Invoke-WebRequest -uri '$UserRelmURL' -UseBasicParsing"
        $UserRealmJson = RunPScript -PSScript $PSScript | Out-Null
     }else{
        #$UserRealmJson= Invoke-WebRequest -uri $UserRelmURL -UseBasicParsing -Proxy $global:ProxyServer
        $PSScript = "Invoke-WebRequest -uri '$UserRelmURL' -UseBasicParsing -Proxy $global:ProxyServer"
        $UserRealmJson = RunPScript -PSScript $PSScript | Out-Null
     }
    
    if(!($UserRealmJson)){
        ''
        Write-Host "Test failed: Could not check domain authentication type." -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: Make sure the device has Internet connectivity." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit  
    }

    $UserRealm = $UserRealmJson.Content | ConvertFrom-Json
    $global:UserRealmMEX = $UserRealm.federation_metadata_url
    $global:FedProtocol = $UserRealm.federation_protocol
    #Check if the domain is Managed
    if ($UserRealm.account_type -eq "Managed"){
        #The domain is Managed
        Write-Host "The configured domain is Managed" -ForegroundColor Green -BackgroundColor Black

        ''
        Write-Host "Checking if the device synced to AAD..." -ForegroundColor Yellow
        $DN=([adsisearcher]"(&(objectCategory=computer)(objectClass=computer)(cn=$env:COMPUTERNAME))").findall().path
        $OGuid = ([ADSI]$DN).ObjectGuid
        $ComputerGUID=(new-object guid(,$OGuid[0])).Guid
        $AADDevice = Get-MsolDevice -DeviceId $ComputerGUID -ErrorAction 'silentlycontinue'
        if ($AADDevice.count -ge 1){
            #The device existing in AAD:
            Write-Host "Test passed: the device object exists on Azure AD." -ForegroundColor Green -BackgroundColor Black
        }else{
            #Device does not exist:
            ###Reregister device to AAD
            Write-Host "Test failed: the device does not exist in your Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
            ''
            Write-Host "Recommended action: Make sure the device is in the sync scope, and it is successfully exported to Azure AD by AAD Connect." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
        }

    }else{
    #The domain is federated
    Write-Host "The configured domain is Federated" -ForegroundColor Green -BackgroundColor Black
    #Testing Federation protocol
    ''
    Write-Host "Tesing WSTrust Protocol..." -ForegroundColor Yellow
    if ($global:FedProtocol -ne "WSTrust"){
        #Not WSTrust
        Write-Host "Test failed: WFTrust protocol is not enabled on federation service configuration." -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: Make sure that your federation service supports WSTrust protocol, and WSTrust is enabled on AAD federated domain configuration." -ForegroundColor Yellow
        Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit
    }else{
        #WSTrust enabled
        Write-Host "Test passed: WSTrust protocol is enabled on federation service configuration." -ForegroundColor Green -BackgroundColor Black
    }


    #Testing MEX URL
    ''
    Write-Host "Tesing Metadata Exchange URI (MEX) URL..." -ForegroundColor Yellow
    $ErrorActionPreference = "SilentlyContinue"
    $WebResponse=""

    #Check if FSName bypassed by proxy
    $ADFSName=$global:UserRealmMEX -Split "https://"
    $ADFSName=$ADFSName[1] -Split "/"
    $FSName=$ADFSName[0]
    $ADFSName=$FSName -split "\."
    $ADFSName[0], $ADFSNameRest=$ADFSName
    $ADFSNameAll = $ADFSNameRest -join '.'
    $ADFSNameAll = "*."+$ADFSNameAll
    $global:FedProxy= $global:Bypass.Contains($FSName) -or $global:Bypass.Contains($ADFSNameAll)

    #If there is no proxy, or FSName bypassed by proxy
    if (($global:ProxyServer -eq "NoProxy") -or ($global:FedProxy)){
        $PSScript = "Invoke-WebRequest -uri $global:UserRealmMEX -UseBasicParsing"
        $WebResponse = RunPScript -PSScript $PSScript
    }else{
        $PSScript = "Invoke-WebRequest -uri $global:UserRealmMEX -UseBasicParsing -Proxy $global:ProxyServer"
        $WebResponse = RunPScript -PSScript $PSScript
    }

    if ((($WebResponse.Content).count) -eq 0 ){
        #Not accessible
        Write-Host "Test failed: MEX URL is not accessible." -ForegroundColor Red -BackgroundColor Black
        ''
        Write-Host "Recommended action: Make sure the MEX URL $global:UserRealmMEX is accessible." -ForegroundColor Yellow
        Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit

    }else{
        #MEX is accessible
        Write-Host "Test passed: MEX URL '$global:UserRealmMEX' is accessible." -ForegroundColor Green -BackgroundColor Black
        ''
        #count of windowstransport
        Write-Host "Tesing windowstransport endpoints on your federation service..." -ForegroundColor Yellow
        if (([regex]::Matches($WebResponse.Content, "windowstransport" )).count -ge 1){
            #windowstransport is enabled
            Write-Host "Test passed: windowstransport endpoint is enabled on your federation service." -ForegroundColor Green -BackgroundColor Black
        }else{
            Write-Host "Test failed: windowstransport endpoints are disabled on your federation service" -ForegroundColor Red -BackgroundColor Black
            ''
            Write-Host "Recommended action: Make sure that windowstransport endpoints are enabled on your federation service." -ForegroundColor Yellow
            Write-Host "Important Note: if your windows 10 version is 1803 or above, device registration will fall back to sync join." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit          
        }
        }
}   
        
    #Check DevReg app
    ''
    Write-Host "Testing Device Registration Service..." -ForegroundColor Yellow
    if ((Get-MsolServicePrincipal -AppPrincipalId 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9).accountenabled){
       Write-Host "Test passed: Device Registration Service is enabled on the tenant" -ForegroundColor Green -BackgroundColor Black 
    }else{
        Write-Host "Test failed: Deice Registration Service is disabled on the tenant" -ForegroundColor red -BackgroundColor Black
        ''
        Write-Host "Recommended action: enable Device Registration Service application on your tenant" -ForegroundColor Yellow
        ''
        ''
        Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        ''
        exit                
    }

    ''
    ''
    Write-Host "Script completed successfully. You can start hybrid Azure AD registration process." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}else{
    #The device is hybrid Azure AD join
    $TenantName = $DSReg | Select-String TenantName | Select-Object -first 1
    $TenantName =($TenantName.tostring() -split ":")[1].trim()
    $hostname = hostname
    Write-Host "Test passed:" $hostname "device is joined to Azure AD tenant that has the name of" $TenantName -ForegroundColor Green -BackgroundColor Black

}

''
Write-Host "Testing the device status on Azure AD..." -ForegroundColor Yellow

CheckMSOnline

#Check the device status on AAD:
$DID = $DSReg | Select-String DeviceId
$DID = ($DID.ToString() -split ":")[1].Trim()
$AADDevice = Get-MsolDevice -DeviceId $DID -ErrorAction 'silentlycontinue'
        
#Check if the device exist:
''
Write-Host "Checking if device exists on AAD..." -ForegroundColor Yellow
if ($AADDevice.count -ge 1){
    #The device existing in AAD:
    Write-Host "Test passed: the device object exists on Azure AD." -ForegroundColor Green -BackgroundColor Black
}else{
    #Device does not exist:
    ###Rejoin device to AAD
    Write-Host "Test failed: the device does not exist in your Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Run 'dsregcmd /leave' and 'dsregcmd /join' commands as admin to perform hybrid Azure AD join procedure again. If you have a Managed domain, make sure the device is in the sync scope." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}

#Check if the device is enabled:
''
Write-Host "Checking if device enabled on AAD..." -ForegroundColor Yellow
if ($AADDevice.Enabled -eq $false){
    ###Enabling device in AAD
    Write-Host "Test failed: the device is not enabled on Azure AD tenant." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended action: Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device." -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit
}else{
        Write-Host "Test passed: the device is enabled on Azure AD tenant." -ForegroundColor Green -BackgroundColor Black
}

#Check if the device is registered (not Pending):
''
Write-Host "Checking device PENDING state..." -ForegroundColor Yellow
[string]$AltSec=$AADDevice.AlternativeSecurityIds
if (-not ($AltSec.StartsWith("X509:"))){
    ###Perform DJ++
    Write-Host "Test failed: the device in 'Pending' state on Azure AD." -ForegroundColor Red -BackgroundColor Black
    ''
    Write-Host "Recommended actions: Device registration process will not trigger as the device feels itself as a registered device. To fix this issue, do the following:" -ForegroundColor Yellow
    Write-Host "                     - Clear the device state by running the command 'dsregcmd /leave' as admin. " -ForegroundColor Yellow
    Write-Host "                     - Run 'dsregcmd /join' command as admin to perform hybrid Azure AD join procedure and re-run the script." -ForegroundColor Yellow
    Write-Host "                       If the issue still persists, check the possible courses on the article: http://www.microsoft.com/aadjerrors" -ForegroundColor Yellow
    ''
    ''
    Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
    ''
    ''
    exit

}else{
        Write-Host "Test passed: the device is not in PENDING state." -ForegroundColor Green -BackgroundColor Black
}


        ''
        Write-Host "Checking dual state..." -ForegroundColor Yellow
        $HAADJTID = $DSReg | Select-String TenantId | Select-Object -first 1
        $WPJTID = $DSReg | Select-String WorkplaceTenantId | Select-Object -first 1
        $WPJ = $DSReg | Select-String WorkplaceJoined
        $WPJ = ($WPJ.tostring() -split ":")[1].trim()
        if (($WPJ -eq "YES") -and ($HAADJTID -eq $WPJTID)){
            Write-Host "The device in dual state." -ForegroundColor Red
            ''
            Write-Host "Recommended action: upgrade your OS to Windows 10 1803 (with KB4489894 applied). In pre-1803 releases, you will need to remove the Azure AD registered state manually before enabling Hybrid Azure AD join by disconnecting the user from Access Work or School Account." -ForegroundColor Yellow
            ''
            ''
            Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
            ''
            ''
            exit
        }elseif ($WPJ -ne "YES"){
            #Check if there is atoken inside the path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com
            if ((Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com -ErrorAction SilentlyContinue).PSPath){
                Write-Host "The device in dual state." -ForegroundColor Red
                ''
                Write-Host "Recommended action: remove the registry key 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\'" -ForegroundColor Yellow
                ''
                ''
                Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
                ''
                ''
                exit                
            }
        }else{
                Write-Host "The device is not in dual state." -ForegroundColor Green
        }



''
''
Write-Host "The device is connected to AAD as hybrid Azure AD joined device, and it is in healthty state." -ForegroundColor Green -BackgroundColor Black
''
''
Write-Host "Script completed successfully." -ForegroundColor Green -BackgroundColor Black
''
''    
}
$global:DomainAuthType=""
$global:MEXURL=""
$global:MEXURLRun=$true
$global:DCTestPerformed=$false
$global:Bypass=""
$global:login=$false
$global:device=$false
$global:enterprise=$false

cls
'========================================================'
Write-Host '        Device Registration Troubleshooter Tool          ' -ForegroundColor Green 
'========================================================'
''
Write-Host "Please provide any feedback, comment or suggestion" -ForegroundColor Yellow
Write-Host
Write-Host "Enter (1) to troubleshoot Azure AD Register" -ForegroundColor Green
''
Write-Host "Enter (2) to troubleshoot Azure AD Join device" -ForegroundColor Green
''
Write-Host "Enter (3) to troubleshoot Hybrid Azure AD Join" -ForegroundColor Green
''
Write-Host "Enter (4) to verify Service Connection Point (SCP)" -ForegroundColor Green
''
Write-Host "Enter (5) to verify the health status of the device" -ForegroundColor Green
''
Write-Host "Enter (6) to Verify Primary Refresh Token (PRT)" -ForegroundColor Green
''
Write-Host "Enter (7) to collect the logs" -ForegroundColor Green
''
Write-Host "Enter (Q) to Quit" -ForegroundColor Green
''

$Num =''
$Num = Read-Host -Prompt "Please make a selection, and press Enter" 

While(($Num -ne '1') -AND ($Num -ne '2') -AND ($Num -ne '3') -AND ($Num -ne '4') -AND ($Num -ne '5') -AND ($Num -ne '6') -AND ($Num -ne '7') -AND ($Num -ne 'Q')){

$Num = Read-Host -Prompt "Invalid input. Please make a correct selection from the above options, and press Enter" 

}

if($Num -eq '1'){
    ''
    Write-Host "Troubleshoot Azure AD Register option has been chosen" -BackgroundColor Black
    ''
    WPJTS
}elseif($Num -eq '2'){
    ''
    Write-Host "Troubleshoot Azure AD Join device option has been chosen" -BackgroundColor Black
    ''
    AADJ
}elseif($Num -eq '3'){
    ''
    Write-Host "Troubleshoot Hybrid Azure AD Join option has been chosen" -BackgroundColor Black
    ''
    DJ++TS
}elseif($Num -eq '4'){
    ''
    Write-Host "Verify Service Connection Point (SCP) has been chosen" -BackgroundColor Black
    ''
    VerifySCP
}elseif($Num -eq '5'){
    ''
    Write-Host "Verify the health status of the device option has been chosen" -BackgroundColor Black
    ''
    DJ++
}elseif($Num -eq '6'){
    ''
    Write-Host "Verify Primary Refresh Token (PRT) option has been chosen" -BackgroundColor Black
    ''
    CheckPRT
}elseif($Num -eq '7'){
    ''
    Write-Host "Collect the logs option has been chosen" -BackgroundColor Black
    ''
    LogsCollection
}