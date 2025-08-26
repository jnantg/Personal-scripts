    Import-Module ExchangeOnlineManagement
    Connect-ExchangeOnline -UserPrincipalName jna@ntg.com



Write-Host "Getting Roomlists and Rooms. This might take a minute..."
$RoomLists = Get-DistributionGroup -ResultSize Unlimited | Where {$_.RecipientTypeDetails -eq "RoomList"}

Write-Host "Please choose a roomlist:"
Write-Host "______________________________________________________"
For ($i=0; $i -lt $RoomLists.Count; $i++)  {
  Write-Host "$($i+1): $($RoomLists[$i].Name)"
}

Write-Host "______________________________________________________"
[int]$number = Read-Host "Press the number to select a roomlist: "
Write-Host "______________________________________________________"

Write-Host "You've selected $($RoomLists[$number-1])."
$ChosenList = $($RoomLists[$number-1])
Write-Host "______________________________________________________"





$Rooms = Get-Mailbox -ResultSize unlimited -Filter "RecipientTypeDetails -eq 'RoomMailbox'" 

Write-Host "Please choose a room:"
Write-Host "______________________________________________________"
For ($i=0; $i -lt $Rooms.Count; $i++)  {
  Write-Host "$($i+1): $($Rooms[$i].Name)"
}


[int]$number = Read-Host "Press the number to select a room: "
Write-Host "______________________________________________________"

Write-Host "You've selected $($Rooms[$number-1])."
$ChosenRoom = $($Rooms[$number-1])
write-host "`n"


Write-Host "______________________________________________________"



Write-Host "You are about to add $($ChosenRoom) to $($ChosenList)"
write-host "`n"
write-host "`n"
Read-Host -Prompt "Press any key to continue or CTRL+C to quit" 


Write-Host "Attempting to add  $($ChosenRoom) to $($ChosenList)"

write-host "`n"

Add-DistributionGroupMember -Identity $ChosenList -Member $ChosenRoom

