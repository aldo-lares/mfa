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