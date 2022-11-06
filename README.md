# MSIExecEoP
Arbitrary File Delete in Windows Installer before 10.0.19045.2193

This bug was not reported to MSFT as i found it 3 days before patch Tuesday :(


Msiexec perform file operation in user controlled directory without impersonation which leads to arbitrary file delete.

Msiexec relies on restrictive DACL inside C:\users\\%username%\appdata\roaming\microsoft\installer directory which are set only to allow everyone group read access, but as user have DELETE privileges on parent directory installer directory can be moved and recreated with permissive DACL.

![image](https://user-images.githubusercontent.com/44291883/200148480-0e06d147-25cd-47ab-884d-6d928e5e2f8d.png)
