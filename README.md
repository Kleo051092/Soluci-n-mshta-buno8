# MSHTA / buno8.ru – Kit de Respuesta y Remediación (Windows)

**Estado:** listo para usar • **Alcance:** triage de alcance, remediación segura y post-auditoría  
**Compatibilidad:** Windows PowerShell 5.1 y PowerShell 7+ (scripts en ASCII)

## Contenido
- `scripts/Triage-MshtaBuno.ps1` — **Fase 0**: triage rápido inicial (detección y recolección mínima).
- `scripts/Audit-MalwareScope-Chrome_v2.ps1` — **Fase 1**: auditoría de alcance (incluye navegador).
- `scripts/Remediate-PostAudit.ps1` — **Fase 2**: remediación/endurecimiento y limpieza de Chrome.
- `scripts/Audit-PostRemediacion-Full_v2.ps1` — **Fase 3**: post-auditoría (solo lectura).
- `docs/Guide.md` — Guía paso a paso.
- `docs/Troubleshooting.md` — Errores comunes y soluciones.
- `docs/IOC.md` — Indicadores relevantes (dominios/comandos).
- `docs/SECURITY.md` — Reporte responsable.
- `LICENSE` — MIT.

> Caso de referencia: infección por **mshta** con URL `s.buno8.ru/...` (familia Wacatac/OfferCore/stealer), políticas de Chrome residuales y posible exfiltración de datos de navegador.

## Uso rápido

### Fase 0 — Triage
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
& ".\scripts\Triage-MshtaBuno.ps1"
```

### Fase 1 — Auditoría de alcance
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
& ".\scripts\Audit-MalwareScope-Chrome_v2.ps1" -DeepChrome -Days 45 -MaxRows 200
```

### Fase 2 — Remediación y endurecimiento
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
& ".\scripts\Remediate-PostAudit.ps1" -AuditRoot "C:\ProgramData\MshtaCleanup\Audit-YYYYMMDD-HHMMSS" `
  -DeepCleanChrome -DisableMshta -HardenScripts -ResetNetwork -FullScan -SfcDismRepair
```

### Fase 3 — Post-auditoría
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
& ".\scripts\Audit-PostRemediacion-Full_v2.ps1" -Days 45
```
```bash
git init
git remote add origin <URL_DEL_REPO>
git add .
git commit -m "Kit respuesta mshta/buno8: triage, auditoría, remediación y post-auditoría"
git branch -M main
git push -u origin main
```
