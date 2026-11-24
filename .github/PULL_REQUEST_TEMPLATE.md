## Qué cambia

<!-- Resumen en una o dos frases. -->

## Fase

- [ ] Fase 1 — Profesionalización (CI, plantillas, docs)
- [ ] Fase 2 — Correcciones probadas en producción
- [ ] Fase 3 — Privacidad y endurecimiento
- [ ] Fase 4 — Operación (desinstalador, tests, Docker)

## Comprobaciones ejecutadas

<!-- Marca solo lo que hayas ejecutado de verdad. -->

- [ ] `powershell -ExecutionPolicy Bypass -File scripts\test_fortress.ps1` (como administrador)
- [ ] `node --check scripts\ai_dns_guard.js`
- [ ] `node --test tests/`
- [ ] `python tools/validate_fortress_config.py`
- [ ] Prueba manual en un equipo real (describe qué se probó)

## Riesgo y vuelta atrás

<!-- ¿Puede dejar el equipo sin DNS? ¿Cómo se revierte? -->

## Notas

<!-- No eliminar funcionalidad existente sin justificarlo aquí. -->
