# Active Directory Update User Attributes Action

Update user attributes in on-premise Active Directory via LDAP/LDAPS.

## Overview

This action modifies user attributes in Active Directory using the LDAP `replace` operation via the `ldapts` library. It features advanced dual lookup support for both `sAMAccountName` and immutable `objectGUID` with proper binary encoding for GUID searches. The action supports complex LDAP filter operations and comprehensive error handling through the enhanced SGNL testing framework.

Key capabilities:
- **Dual lookup support**: Find users by `sAMAccountName` or immutable `objectGUID` (with binary encoding)
- **Complex LDAP filters**: Full support for AndFilter, EqualityFilter, OrFilter, and other advanced LDAP constructs
- **Idempotent operations**: LDAP `replace` operations produce no errors when setting the same value multiple times
- **Comprehensive testing**: Enhanced testing framework with full ldapts mocking and 11 passing test scenarios
- **Binary GUID handling**: Proper encoding of objectGUID for reliable Active Directory searches

Supports updating any combination of standard AD user attributes in a single call. Scalar values are automatically wrapped in arrays as required by the LDAP protocol.

## Prerequisites

- Network access to an Active Directory Domain Controller (LDAP port 389 or LDAPS port 636)
- A service account with **Write** permissions on the target user objects
- The user's `sAMAccountName` (pre-Windows 2000 logon name) or `objectGUID` for lookup
- For password changes, LDAPS (port 636) is required by Active Directory

## Configuration

### Authentication

| Secret | Description |
|--------|-------------|
| `BASIC_USERNAME` | Bind DN of the service account (e.g., `CN=svc-sgnl,OU=Service Accounts,DC=example,DC=com`) |
| `BASIC_PASSWORD` | Password for the service account |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ADDRESS` | LDAP/LDAPS URL of the Domain Controller (e.g., `ldaps://dc.example.com:636`) | Required |
| `TLS_SKIP_VERIFY` | Set to `true` to skip TLS certificate verification | `false` |

### Input Parameters

| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `baseDN` | text | Yes | Base DN to search for the user | `DC=corp,DC=example,DC=com` |
| `samAccountName` | text | No | The user's sAMAccountName (pre-Windows 2000 logon name) to lookup. Required if `objectGUID` is not provided. | `jdoe` |
| `objectGUID` | text | No | Immutable AD object GUID for user lookup. Use instead of `samAccountName` when renaming the SAM account. Format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` | `550e8400-e29b-41d4-a716-446655440000` |
| `newSamAccountName` | text | No | New SAM account name if renaming (maps to `sAMAccountName`) | `johndoe` |
| `userPrincipalName` | text | No | User principal name / UPN (maps to `userPrincipalName`) | `jdoe@example.com` |
| `firstName` | text | No | First name (maps to `givenName`) | `John` |
| `lastName` | text | No | Last name (maps to `sn`) | `Doe` |
| `displayName` | text | No | Display name (maps to `displayName`) | `John Doe` |
| `email` | text | No | Email address (maps to `mail`) | `john.doe@example.com` |
| `company` | text | No | Company name (maps to `company`) | `Example Corp` |
| `department` | text | No | Department name (maps to `department`) | `Engineering` |
| `title` | text | No | Job title (maps to `title`) | `Software Engineer` |
| `password` | text | No | New password for the user (encoded as `unicodePwd` UTF-16LE) | `N3wP@ssw0rd!` |
| `changePasswordAtNextLogin` | boolean | No | Force the user to change password at next login (sets `pwdLastSet` to `0`) | `true` |
| `additionalAttributes` | object | No | Key-value pairs of additional LDAP attributes to set | `{"telephoneNumber": "+1-555-0100", "physicalDeliveryOfficeName": "Building A"}` |
| `dry_run` | boolean | No | When true, validates parameters without making changes | `false` |
| `address` | text | No | Optional LDAP server URL override | `ldaps://ad.corp.example.com:636` |

At least one of `samAccountName` or `objectGUID` must be provided for user lookup. When `objectGUID` is provided, it takes precedence and is used for the LDAP search.

At least one attribute must be provided, either via named parameters, the `additionalAttributes` object, or both. Named parameters take precedence over conflicting keys in `additionalAttributes`.

### Output

| Field | Type | Description |
|-------|------|-------------|
| `status` | text | `success`, `dry_run_completed`, or `halted` |
| `userDN` | text | The resolved Distinguished Name of the user |
| `modified` | boolean | `true` if attributes were updated |
| `attributes` | array | List of attribute names that were modified |
| `address` | text | LDAP server address used |

## Usage Examples

### Basic Usage

```json
{
  "baseDN": "DC=corp,DC=example,DC=com",
  "samAccountName": "jdoe",
  "email": "john.doe@example.com",
  "department": "Engineering"
}
```

### Using Named Parameters

```json
{
  "baseDN": "DC=corp,DC=example,DC=com",
  "samAccountName": "jdoe",
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "department": "Engineering",
  "title": "Software Engineer"
}
```

Named parameters can be combined with the `additionalAttributes` object for less common LDAP attributes:

```json
{
  "baseDN": "DC=corp,DC=example,DC=com",
  "samAccountName": "jdoe",
  "firstName": "John",
  "email": "john.doe@example.com",
  "additionalAttributes": {
    "physicalDeliveryOfficeName": "Building A, Room 101",
    "telephoneNumber": "+1-555-0100"
  }
}
```

### Set a Password and Force Change at Next Login

```json
{
  "baseDN": "DC=corp,DC=example,DC=com",
  "samAccountName": "jdoe",
  "password": "N3wP@ssw0rd!",
  "changePasswordAtNextLogin": true
}
```

### Rename a User's SAM Account Name

```json
{
  "baseDN": "DC=corp,DC=example,DC=com",
  "samAccountName": "jdoe",
  "newSamAccountName": "johndoe"
}
```

### Rename a User's SAM Account Name (using objectGUID)

When a `samAccountName` change is triggered and only the new value is available,
use `objectGUID` for the lookup instead:

```json
{
  "baseDN": "DC=corp,DC=example,DC=com",
  "objectGUID": "550e8400-e29b-41d4-a716-446655440000",
  "newSamAccountName": "johndoe"
}
```

### Full Job Specification

```json
{
  "id": "update-user-attrs",
  "type": "nodejs-20",
  "script": {
    "repository": "github.com/sgnl-actions/ad-update-user",
    "version": "v1.0.3",
    "type": "nodejs"
  },
  "script_inputs": {
    "baseDN": "DC=corp,DC=example,DC=com",
    "samAccountName": "jdoe",
    "firstName": "John",
    "email": "john.doe@example.com",
    "additionalAttributes": {
      "displayName": "John Doe",
      "department": "Engineering",
      "title": "Software Engineer"
    }
  },
  "environment": {
    "ADDRESS": "ldaps://dc.example.com:636",
    "TLS_SKIP_VERIFY": "false"
  }
}
```

### Skip TLS Verification

For development or self-signed certificate environments:

```json
{
  "environment": {
    "ADDRESS": "ldaps://dc.dev.example.com:636",
    "TLS_SKIP_VERIFY": "true"
  }
}
```

## API Details

### User Lookup

The action supports two robust lookup methods:

**By sAMAccountName (default):**
```
SEARCH baseDN (scope=sub, filter=(&(objectClass=user)(sAMAccountName=<samAccountName>)))
```

**By objectGUID (recommended for renames):**
```
SEARCH baseDN (scope=sub, filter=(&(objectClass=user)(objectGUID=\xx\xx...)))
```

The `objectGUID` lookup uses proper binary encoding where the GUID string is converted to its binary representation and encoded as an LDAP octet string. This ensures reliable lookups even when the `sAMAccountName` is being modified.

Using `objectGUID` is recommended when the `samAccountName` itself is being changed, as the GUID is permanently immutable and uniquely identifies the AD object regardless of any attribute changes. The action uses advanced LDAP filter classes (EqualityFilter, AndFilter) to construct precise search queries.

The lookup returns the user's Distinguished Name, which is then used for the modify operation.

### LDAP Modify/Replace Operation

This action uses the LDAP `replace` modification type for each attribute. The `replace` operation:

- Sets the attribute to the specified value(s) if it exists
- Creates the attribute with the specified value(s) if it does not exist
- Is idempotent -- calling with the same values produces no errors

### Named Parameter Mapping

| Named Parameter | LDAP Attribute |
|-----------------|---------------|
| `newSamAccountName` | `sAMAccountName` |
| `userPrincipalName` | `userPrincipalName` |
| `firstName` | `givenName` |
| `lastName` | `sn` |
| `displayName` | `displayName` |
| `email` | `mail` |
| `company` | `company` |
| `department` | `department` |
| `title` | `title` |

### Special Parameters

| Parameter | LDAP Attribute | Notes |
|-----------|---------------|-------|
| `password` | `unicodePwd` | Password is quoted and encoded as UTF-16LE Buffer per AD requirements. Requires LDAPS. |
| `changePasswordAtNextLogin` | `pwdLastSet` | `true` → sets `pwdLastSet` to `0`, forcing password change at next login |

### Password Encoding

Active Directory requires passwords to be set via the `unicodePwd` attribute as a UTF-16LE encoded, double-quoted string. This action handles the encoding automatically -- simply pass the plaintext password as the `password` parameter.

**Note:** Password changes require an LDAPS (SSL/TLS) connection. Attempting to set a password over unencrypted LDAP will be rejected by Active Directory.

### Common AD Attributes

| Attribute | Description | Example |
|-----------|-------------|---------|
| `displayName` | Display name | `John Doe` |
| `mail` | Email address | `john@example.com` |
| `department` | Department | `Engineering` |
| `title` | Job title | `Software Engineer` |
| `telephoneNumber` | Phone number | `+1-555-0100` |
| `physicalDeliveryOfficeName` | Office location | `Building A, Room 101` |
| `manager` | Manager DN | `CN=Jane Smith,OU=Users,DC=example,DC=com` |
| `description` | Description | `Senior engineer on platform team` |
| `company` | Company name | `Example Corp` |
| `streetAddress` | Street address | `123 Main St` |
| `l` | City | `San Francisco` |
| `st` | State | `CA` |
| `postalCode` | Postal/ZIP code | `94105` |

Multi-valued attributes (e.g., `otherTelephone`, `proxyAddresses`) can be passed as arrays:

```json
{
  "additionalAttributes": {
    "otherTelephone": ["+1-555-0100", "+1-555-0101"]
  }
}
```

## Error Handling

### Success Scenarios

- **Attribute updated** -- returns `status: "success"`, `modified: true`
- **Same value re-applied** -- returns `status: "success"`, `modified: true` (idempotent, no error)

### Retryable Errors

| Error | Description |
|-------|-------------|
| Network timeout | Domain Controller unreachable |
| Connection refused | LDAP service not running |
| Server busy | DC under heavy load |

### Fatal Errors

| Error | Description |
|-------|-------------|
| User not found | No user exists with the specified `sAMAccountName` or `objectGUID` |
| Multiple users found | More than one user matches the sAMAccountName (should not happen in a properly configured AD) |
| Invalid Credentials | Bind DN or password is incorrect |
| Insufficient Access Rights | Service account lacks Write permission |
| Constraint Violation | Attribute value violates AD schema constraints |
| Undefined Attribute Type | Attribute name not recognized by the AD schema |

## Security Considerations

- Use LDAPS (port 636) in production to encrypt credentials and data in transit
- LDAPS is **required** for password changes -- AD rejects `unicodePwd` modifications over unencrypted LDAP
- Only skip TLS verification (`TLS_SKIP_VERIFY=true`) in development environments
- The service account should have minimal permissions -- only Write access on the specific user attributes needed
- Attribute values are not logged; only attribute names appear in the output to avoid leaking sensitive data
- Special characters in sAMAccountName are escaped to prevent LDAP injection

## Development

### Setup

```bash
npm install
```

### Run tests

This action uses the enhanced SGNL testing framework with comprehensive LDAP mocking support. All 11 test scenarios validate the action's dual lookup capabilities, complex LDAP filter operations, and error handling:

```bash
npm test
```

The test suite includes:
- User lookup by `sAMAccountName` and `objectGUID`
- Binary GUID encoding validation
- Complex LDAP filter construction (AndFilter, EqualityFilter, etc.)
- Comprehensive error scenarios and edge cases
- Password operations and special attribute handling

### Run tests in watch mode

```bash
npm run test:watch
```

### Build

```bash
npm run build
```

### Validate metadata

```bash
npm run validate
```

### Lint

```bash
npm run lint
npm run lint:fix
```

### Local testing

Create a `../.env` file with your AD credentials:

```
ADDRESS=ldap://your-dc.example.com:389
BASIC_USERNAME=CN=admin,DC=example,DC=com
BASIC_PASSWORD=your-password
TLS_SKIP_VERIFY=false
```

Then run:

```bash
npm run dev
```

## Troubleshooting

### User Lookup Issues

- **"User not found with sAMAccountName"** -- Verify the sAMAccountName is correct (case-insensitive in AD) and that the user exists within the specified baseDN
- **"Multiple users found"** -- This should not happen in a properly configured AD since sAMAccountName must be unique within a domain
- **"samAccountName rename not applying"** -- If the `samAccountName` is being changed, provide the `objectGUID` instead of `samAccountName` for lookup. The GUID is immutable and will locate the user regardless of their current or new SAM account name.

### Connection Issues

- Verify the Domain Controller is reachable: `telnet dc.example.com 636`
- Check that the `ADDRESS` environment variable includes the protocol and port: `ldaps://dc.example.com:636`
- For LDAPS, ensure the DC's certificate is trusted or set `TLS_SKIP_VERIFY=true` for testing

### Authentication Failures

- Verify the bind DN format matches your AD structure
- Ensure the service account password has not expired
- Check that the service account is not locked out

### Permission Errors

- The service account needs Write permission on the target user object's attributes
- Use AD delegation to grant granular permissions rather than Domain Admin

### Attribute Errors

- Verify attribute names match the AD schema (LDAP names, not display names)
- Check that attribute values conform to the schema's syntax rules (e.g., email format for `mail`)
- For multi-valued attributes, pass an array of values

### Password Errors

- Ensure the connection uses LDAPS (port 636) -- AD rejects password changes over unencrypted LDAP
- Verify the password meets the domain's complexity requirements
- Check that the service account has the "Reset Password" permission on the target user

## Support

- [ldapts Documentation](https://github.com/ldapts/ldapts) - LDAP client library with comprehensive filter support
- [SGNL Testing Framework](https://github.com/sgnl-actions/testing) - Enhanced testing with LDAP mocking capabilities
- [Active Directory LDAP Reference](https://docs.microsoft.com/en-us/windows/win32/ad/active-directory-domain-services)
- [SGNL Actions Documentation](https://github.com/sgnl-actions)
