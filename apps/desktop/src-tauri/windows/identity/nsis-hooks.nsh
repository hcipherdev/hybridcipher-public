!macro NSIS_HOOK_PREINSTALL
  nsExec::ExecToStack 'powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command "if ([Environment]::OSVersion.Version.Build -lt 19041) { exit 1 }"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "HybridCipher cloud-file mounts require Windows 10 build 19041 or newer."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToStack 'powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\register-identity.ps1" -Mode Install -InstallDirectory "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "Windows package identity registration failed. Repair the certificate/package configuration and run setup again.$\r$\n$1"
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToStack '"$INSTDIR\hybridcipher-desktop.exe" --unregister-shell-roots'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "HybridCipher could not remove all Explorer sync-root registrations.$\r$\n$1"
    Abort
  ${EndIf}
  nsExec::ExecToStack 'powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$INSTDIR\register-identity.ps1" -Mode Uninstall -InstallDirectory "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "HybridCipher could not remove its Windows package identity.$\r$\n$1"
    Abort
  ${EndIf}
!macroend
