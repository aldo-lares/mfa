# mfa

Local identity pilot where Keycloak federates users from OpenLDAP and requires TOTP before issuing an OIDC session to the web application. Microsoft Entra workforce login remains available as a separate employee identity boundary.

## Build and test

```sh
mvn test
```

## Run

Configure the LDAP connection with environment variables or matching Java system properties:

| Environment variable | System property | Description |
| --- | --- | --- |
| `LDAP_URL` | `ldap.url` | LDAP server URL, for example `ldap://localhost:389` |
| `LDAP_BASE_DN` | `ldap.baseDn` | Base DN used to search users, for example `ou=people,dc=example,dc=org` |
| `LDAP_USER_SEARCH_FILTER` | `ldap.userSearchFilter` | LDAP search filter containing `{0}` for the user value. Defaults to `(uid={0})` |
| `LDAP_BIND_DN` | `ldap.bindDn` | Optional service account DN for searching |
| `LDAP_BIND_PASSWORD` | `ldap.bindPassword` | Optional service account password for searching |
| `LDAP_CONTEXT_FACTORY` | `ldap.contextFactory` | Optional JNDI context factory. Defaults to `com.sun.jndi.ldap.LdapCtxFactory` |
| `SERVICE_ADDRESS` | `service.address` | SOAP endpoint address. Defaults to `http://0.0.0.0:8080/auth` |

The default HTTP service address is intended for local development. Production deployments must protect SOAP credentials with transport-level security, such as HTTPS/TLS termination for the SOAP endpoint and `ldaps://` or an equivalent protected connection to LDAP.

Start the SOAP endpoint:

```sh
mvn compile exec:java -Dexec.mainClass=com.github.aldolares.mfa.AuthenticationServiceApplication
```

The WSDL is available at `http://localhost:8080/auth?wsdl`. The SOAP operation is `authenticate(user, password)` and returns `true` only when the user exists in LDAP and the supplied password can bind as that user. Invalid users or passwords return `false`; LDAP configuration or infrastructure failures are returned as SOAP faults.

## Start the local solution

When the solution includes the LDAP container and additional services, use Docker Compose as the single local entry point:

```powershell
docker compose up --build
```

Compose starts OpenLDAP, PostgreSQL, Keycloak, the legacy Java SOAP backend, and the web frontend:

- Frontend: `http://localhost:3000`
- Keycloak administration: `http://localhost:8081/admin`
- Backend WSDL: `http://localhost:8080/auth?wsdl`

The development LDAP contains users `alice` through `jack`, all with password `password`. Select **Acceso para clientes con MFA**, sign in with an LDAP account, and scan the QR code with Microsoft Authenticator, Google Authenticator, or another TOTP application. The first login cannot complete until TOTP enrollment succeeds; subsequent logins require both the LDAP password and a current TOTP code.

The customer flow uses the `mfa-secure` Keycloak theme under `docker/keycloak/themes`. It presents a compact VPN-client-style sequence: LDAP username and password first, then a separate one-time-code screen. Keep credential forms in Keycloak when changing this experience; the Express frontend must only initiate and validate the OIDC flow.

Customer authentication uses Authorization Code with PKCE through Keycloak. OpenLDAP remains the source for passwords and profile attributes, while Keycloak stores the second-factor credential and emits the signed identity token. The application never receives the LDAP password or TOTP code. Direct `POST /api/authenticate` access is disabled to prevent bypassing MFA; the SOAP backend remains only as a legacy internal component during migration.

The frontend supports two identity boundaries:

- `workforce` uses the organization's Microsoft Entra workforce tenant for employees.
- `customer` uses the local Keycloak realm backed by OpenLDAP and TOTP.

Create an app registration for workforce and configure `http://localhost:3000/auth/workforce/callback` as its Web redirect URI. Create a local `.env` based on `.env.example`; put development secrets only in `.env`, which is ignored by Git. The Keycloak values in Compose are development defaults and must be replaced outside local development.

```powershell
Copy-Item .env.example .env
# Edit .env locally and replace workforce, Keycloak admin/database, client, and session secrets.
docker compose up --build
```

User authorization must be keyed by immutable `issuer` and `subject` claims, not by email address or domain. For production, use HTTPS, LDAPS, a managed secret store, an external session store, PostgreSQL backups, and a supported highly available Keycloak deployment. Port 389 and the legacy SOAP endpoint must not be exposed publicly.

Stop the environment with:

```powershell
docker compose down
```

The LDAP initializer is idempotent across normal restarts. To reset LDAP users or all Keycloak enrollments after changing bootstrap configuration, remove Compose volumes before starting again:

```powershell
docker compose down --volumes
```
