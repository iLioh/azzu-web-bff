# OIDC por certificado: implementación local DEV

> Informe histórico de implementación. Actualización 2026-10-02: certificado OIDC creado en Key Vault y certificado público registrado en Entra; loader/firma probados por separado. No repetir las intervenciones de emisión/registro listadas abajo. Login navegador, logout federado y step-up real siguen pendientes. Ver README de infraestructura para versiones y estado actual.

## Hecho

- Modo de credencial explícito `Certificate`, sin fallback a ClientSecret ni a credencial CLI/IMDS.
- Certificado separado `azzu-web-bff-dev-oidc`, CN homónimo, RSA >=3072, no CA, digitalSignature, fechas y pin SHA-256 verificados. El certificado Mapping no se acepta.
- Loader de secret PFX de versión fija en Key Vault usando Workload Identity explícita, timeout global 30s, retries acotados y sin logging de contenido. Importación EphemeralKeySet, buffer PFX borrado; no archivo o Kubernetes Secret.
- Assertion JWT firmada PS256, header x5t#S256, issuer/subject Client ID, audience token endpoint fijado y comprobado contra discovery; jti nuevo por intercambio, duración 2 minutos. Ninguna identidad/DNI del cliente se introduce en esa assertion.
- Hook real `OnAuthorizationCodeReceived`: agrega client_assertion/type, elimina client_secret y preserva code/verifier. Middleware continúa redención y validación; no se implementa un protocolo de login propio.
- Fail closed en arranque si se selecciona Certificate sin configuración/material válido. El default previo permanece para pruebas/dev; no se activó login falso ni certificado synthetic en aplicación real.
- Ejemplo público de configuración deliberadamente incompleto sin versión/huella; no cargarlo hasta existir la credencial real. Política Self dedicada DEV, tres meses y nueva clave; no ejecutar automáticamente ni usar esta política como aprobación productiva.

## Aún no hecho

No se creó certificado OIDC en Azure, no se agregó keyCredential Entra, no se desplegó BFF ni infraestructura. No hay prueba interactiva Entra/Keycloak/callback. No se implementó refresh/token store, logout federado, sesiones distribuidas, ni conexión Banking API. No se modificó Mobile ni recursos compartidos.

## Siguiente intervención acotada que requiere aprobación

1. Desde entorno privado autorizado, comprobar vault Disabled y permisos actuales; crear únicamente `azzu-web-bff-dev-oidc` con la política adjunta si no existe ni tiene pending. No sobrescribir versiones existentes ni crear roles como workaround.
2. Exportar únicamente certificado público. Registrar de forma ADITIVA su keyCredential en app `81eff91b-a991-4f09-a56c-f42fa2e230aa` del tenant cliente. Conservar credentials/callbacks/user flows y piloto/Mobile.
3. Documentar version/hash/expiry públicas y probar carga/PS256 desde identidad BFF. No loguear assertion ni exportar PFX del entorno autorizado.
4. Despliegue privado BFF y routing same-origin requieren gate posterior separado. Mantener una réplica/HPA off.
5. Login real requiere inspección minimizada de claims emitidos por Keycloak/Entra: impedir DNI en subject/profile/login_hint/logs. Certificado OIDC no garantiza esa privacidad. Si la superficie identity termina TLS en cloud, diferenciar tránsito de almacenamiento; no afirmar ausencia absoluta de tránsito.

La emisión Self para OIDC DEV no requiere que Aldo firme como Mapping: son destinatarios y claves diferentes. Definir renovación y reinicio controlado antes del vencimiento; loader no hace rotación silenciosa.

## Pruebas y límites

Build Release inicial: 0 errores/0 warnings. Suite final: 93 aprobadas, 0 fallidas, 0 omitidas (84 anteriores +9 nuevos casos).

Nuevos casos: firma PS256 y claims técnicos/lifetime/jti; dos destinos inválidos; rechazo de certificado Mapping; pin inválido y falta de certificado runtime; hook OIDC code-redemption con PKCE y sin secreto; configuración ambigua/destino incorrecto; loader con versión fija/PFX y rechazo de secret deshabilitado.

Son pruebas locales con certificados sintéticos. No prueban registro público en Entra, token exchange real ni login navegador. No hay push/commit. Rollback: revertir únicamente el diff OIDC de esta entrega preservando cambios mTLS y previos.

Referencia del formato de assertion: https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
