# IOC (Indicators of Compromise)

- Dominio observado: `s.buno8.ru`
- Artefactos: `mshta.exe`, `.hta`, `wscript.exe`, `cscript.exe`, `powershell.exe -enc`, `rundll32 ... javascript`, `bitsadmin`, `certutil -urlcache`.
- Persistencias: Tareas (Actions), Run/RunOnce, WMI (consumers/filters/bindings), Startup.
- Rastros: Prefetch `MSHTA*.pf`, INetCache con `.hta` o `buno8.ru`.
- Datos en riesgo: BDs de navegador (Chrome/Edge) `Login Data`, `Cookies`, `Web Data`, `History`, `Downloads`.
