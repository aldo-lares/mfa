# mfa

Basic Java SOAP web service for authenticating a user against an OpenLDAP directory.

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

The current Compose setup starts OpenLDAP, the Java SOAP backend, and a simple web frontend. Open the frontend at `http://localhost:3000`; it validates credentials through the backend and shows a basic profile screen. The backend WSDL is available at `http://localhost:8080/auth?wsdl`. The development LDAP contains `alice` with password `password`, so the credentials can be used for an end-to-end smoke test. These credentials and the exposed LDAP port are for local development only.

LDAP authentication continues through the SOAP service. Microsoft Entra authentication uses the interactive Authorization Code flow with PKCE in the frontend, allowing Conditional Access to require MFA. The application never receives the user's Entra password or MFA code.

Configure the App Registration with the Web redirect URI `http://localhost:3000/auth/callback`, then create a local `.env` based on `.env.example`. Put the client secret only in `.env`; the file is ignored by Git.

```powershell
Copy-Item .env.example .env
# Edit .env locally and replace ENTRA_CLIENT_SECRET and SESSION_SECRET.
docker compose up --build
```

Select **Continue with Microsoft** to sign in through Entra. MFA must be required through an Entra Conditional Access policy assigned to this application. For production, use HTTPS, a certificate or managed secret store, and a persistent session store instead of the default in-memory development store.

Stop the environment with:

```powershell
docker compose down
```

To reset the LDAP data after changing the bootstrap LDIF, remove the containers and volumes used by the Compose project before starting it again:

```powershell
docker compose down --volumes
```