copy vmloader.sys "C:\vmloader.sys"
copy hidden.sys "C:\hidden.sys"
copy hiddentests.exe "C:\hiddentests.exe"
sc create vmloader binPath= "\??\c:\vmloader.sys" type= "kernel" start="system"
sc start vmloader
sc create hidden binPath= "\??\c:\hidden.sys" type= "kernel" start="system"
sc start hidden
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v HiddenTests /t REG_SZ /d C:\hiddentests.exe /f