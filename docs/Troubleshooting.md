# Troubleshooting

- **'Token ? inesperado'**: usa scripts `*_v2.ps1` (compatibles con Windows PowerShell 5.1) o `pwsh` (PowerShell 7+).
- **Parámetros no reconocidos**: pon primero el script, luego los switches. Ej.:  
  `& ".\scripts\Remediate-PostAudit.ps1" -AuditRoot ... -DeepCleanChrome ...`
- **Permisos**:  
  `Set-ExecutionPolicy Bypass -Scope Process -Force` y `Unblock-File` si fuese necesario.
- **Escaneo Defender tarda**: normal. Para ver progreso, lee el último log en `C:\ProgramData\MshtaCleanup\`.
