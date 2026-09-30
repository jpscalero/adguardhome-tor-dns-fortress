# Contribuir a AdGuard Home DNS Fortress

¡Gracias por tu interés en mejorar este proyecto! Agradecemos contribuciones enfocadas en privacidad, seguridad DNS, estabilidad del watchdog y mitigación de censura.

## Reglas de Contribución

1. **PowerShell y Codificación**:
   - Todo script de PowerShell (`scripts/*.ps1`) DEBE guardarse en formato **UTF-8 con BOM** (`0xEF, 0xBB, 0xBF`) para garantizar compatibilidad con Windows PowerShell 5.1 y PowerShell Core (7+).
   - Verifica la sintaxis con el parser de PowerShell antes de enviar un PR:
     ```powershell
     $t=$null; $e=$null; [System.Management.Automation.Language.Parser]::ParseFile("scripts/archivo.ps1", [ref]$t, [ref]$e)
     ```

2. **JavaScript (Node.js)**:
   - Mantén la filosofía **stdlib-only** en runtime (sin dependencias externas añadidas al `package.json` para ejecución).
   - Valida la sintaxis con:
     ```powershell
     node --check scripts/ai_dns_guard.js
     node --check scripts/decoy_dns.js
     ```

3. **Sin Fuga de Secretos**:
   - Nunca hagas commit de contraseñas, hashes bcrypt reales, IPs privadas específicas de tu red o claves API.
   - Utiliza variables de entorno o el archivo `config/.env.example` como plantilla.

4. **Commits y PRs**:
   - Usa Conventional Commits (`fix(...)`, `feat(...)`, `docs(...)`, `test(...)`).
   - Describe con claridad el problema resuelto y añade pruebas de verificación.
