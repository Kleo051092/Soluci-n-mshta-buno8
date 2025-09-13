# Guía de Implementación y Operación

## 0) Fase 0 — Triage rápido
Objetivo: validación inmediata y recolección mínima para confirmar indicios (mshta/hta, claves Run, Tasks).
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
& ".\scripts\Triage-MshtaBuno.ps1"
```

## 1) Fase 1 — Auditoría de alcance
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
& ".\scripts\Audit-MalwareScope-Chrome_v2.ps1" -DeepChrome -Days 45 -MaxRows 200
```

## 2) Fase 2 — Remediación y endurecimiento
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
& ".\scripts\Remediate-PostAudit.ps1" -AuditRoot "C:\ProgramData\MshtaCleanup\Audit-YYYYMMDD-HHMMSS" `
  -DeepCleanChrome -DisableMshta -HardenScripts -ResetNetwork -FullScan -SfcDismRepair
```

## 3) Fase 3 — Post-auditoría
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
& ".\scripts\Audit-PostRemediacion-Full_v2.ps1" -Days 45
```

**Evidencias**: conserva ZIPs de `Remediate-Evidence-*` y `PostAudit-*`.
