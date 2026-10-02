# Verificación independiente: cookies y sesión BFF

## Alcance

Se añadieron pruebas de integración locales con el handler Cookie real,
`DevelopmentTicketStore`, antiforgery y endpoints de la aplicación. A diferencia
de los smoke tests anteriores, estas pruebas no sustituyen la autenticación por
un handler que acepta headers sintéticos en cada petición.

El emisor sintético de sesión reside exclusivamente en el assembly de tests,
mediante `IStartupFilter` registrado por la fixture. No se añadió endpoint de
login de prueba al código API ni una vía de acceso para usuarios reales.

## Casos nuevos

- Cookie Secure, HttpOnly, Path=/, sin Domain.
- Consulta de sesión autenticada con respuesta no-store.
- Logout con CSRF y rechazo posterior de una copia de la cookie anterior:
  comprueba revocación del ticket server-side, no solo borrado en el navegador.
- Token antiforgery de otra identidad no permite cerrar la sesión de la víctima.
- Identidad sin vínculo y outage de Mapping conservan la sesión y permiten
  cerrar sesión mediante el bootstrap CSRF independiente de Mapping.
- Cookie manipulada rechazada.
- Ticket expirado rechazado.
- Bootstrap CSRF anónimo rechazado sin emisión de XSRF-TOKEN.

## Ejecución

Resultado: 73 pruebas aprobadas, 0 fallidas (7 casos nuevos). Build Release:
0 warnings y 0 errores. `git diff --check` sin errores.

```powershell
dotnet build Azzu.WebBff.sln -c Release
dotnet test Azzu.WebBff.sln -c Release --no-build
```

Estas pruebas no verifican Angular en navegador, OIDC real, logout federado,
Banking API, almacenamiento distribuido, persistencia ni infraestructura Azure.
El Mapping de estas fixtures es sintético. No sustituye la entrega de Aldo/Sara.

No se hizo commit, push, despliegue ni cambio de Azure/Mobile/on-premise.
El store DEV sigue limitado a una instancia y producción permanece bloqueada.
