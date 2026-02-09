import { jest, describe, test, expect, beforeEach } from '@jest/globals';

const mockBind = jest.fn();
const mockUnbind = jest.fn();
const mockModify = jest.fn();

jest.unstable_mockModule('ldapts', () => ({
  Client: jest.fn().mockImplementation(() => ({
    bind: mockBind,
    unbind: mockUnbind,
    modify: mockModify
  })),
  Change: jest.fn().mockImplementation((opts) => ({
    operation: opts.operation,
    modification: opts.modification
  })),
  Attribute: jest.fn().mockImplementation((opts) => ({
    type: opts.type,
    values: opts.values
  }))
}));

const mockGetBaseURL = jest.fn().mockReturnValue('ldaps://dc.example.com:636');

jest.unstable_mockModule('@sgnl-actions/utils', () => ({
  getBaseURL: mockGetBaseURL
}));

const { default: script } = await import('../src/script.mjs');
const { Client } = await import('ldapts');

describe('AD Update User Script', () => {
  const mockContext = {
    environment: {
      ADDRESS: 'ldaps://dc.example.com:636'
    },
    secrets: {
      LDAP_BIND_DN: 'CN=admin,DC=example,DC=com',
      LDAP_BIND_PASSWORD: 'password123'
    },
    outputs: {}
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockBind.mockResolvedValue(undefined);
    mockUnbind.mockResolvedValue(undefined);
    mockModify.mockResolvedValue(undefined);
    mockGetBaseURL.mockReturnValue('ldaps://dc.example.com:636');
  });

  describe('invoke handler', () => {
    test('should successfully update a single attribute', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: { displayName: 'John Updated' }
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.userDN).toBe('CN=John Doe,OU=Users,DC=example,DC=com');
      expect(result.modified).toBe(true);
      expect(result.attributes).toEqual(['displayName']);
      expect(mockModify).toHaveBeenCalledWith(
        'CN=John Doe,OU=Users,DC=example,DC=com',
        [
          {
            operation: 'replace',
            modification: { type: 'displayName', values: ['John Updated'] }
          }
        ]
      );
    });

    test('should successfully update multiple attributes', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: {
          displayName: 'John Updated',
          mail: 'john.updated@example.com',
          department: 'Engineering'
        }
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toEqual(['displayName', 'mail', 'department']);
      expect(mockModify).toHaveBeenCalledWith(
        'CN=John Doe,OU=Users,DC=example,DC=com',
        [
          { operation: 'replace', modification: { type: 'displayName', values: ['John Updated'] } },
          { operation: 'replace', modification: { type: 'mail', values: ['john.updated@example.com'] } },
          { operation: 'replace', modification: { type: 'department', values: ['Engineering'] } }
        ]
      );
    });

    test('should throw on empty additionalAttributes object', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: {}
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        'At least one attribute must be provided'
      );
      expect(mockBind).not.toHaveBeenCalled();
    });

    test('should throw on missing attributes', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        'At least one attribute must be provided'
      );
      expect(mockBind).not.toHaveBeenCalled();
    });

    test('should propagate LDAP error code 32 (no such object)', async () => {
      mockModify.mockRejectedValue(
        Object.assign(new Error('No such object'), { code: 32 })
      );

      const params = {
        userDN: 'CN=Nonexistent,OU=Users,DC=example,DC=com',
        additionalAttributes: { displayName: 'Test' }
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('No such object');
    });

    test('should propagate LDAP error code 19 (constraint violation)', async () => {
      mockModify.mockRejectedValue(
        Object.assign(new Error('Constraint violation'), { code: 19 })
      );

      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: { mail: 'invalid' }
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Constraint violation');
    });

    test('should propagate LDAP error code 17 (undefined attribute type)', async () => {
      mockModify.mockRejectedValue(
        Object.assign(new Error('Undefined attribute type'), { code: 17 })
      );

      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: { nonExistentAttr: 'value' }
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Undefined attribute type');
    });

    test('should propagate bind failure and still call unbind', async () => {
      mockBind.mockRejectedValue(new Error('Bind failed: invalid credentials'));

      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: { displayName: 'Test' }
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Bind failed: invalid credentials');
      expect(mockUnbind).toHaveBeenCalled();
    });

    test('should throw on missing LDAP_BIND_DN', async () => {
      const context = {
        ...mockContext,
        secrets: { ...mockContext.secrets, LDAP_BIND_DN: '' }
      };

      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: { displayName: 'Test' }
      };

      await expect(script.invoke(params, context)).rejects.toThrow('LDAP_BIND_DN secret is required');
    });

    test('should throw on missing LDAP_BIND_PASSWORD', async () => {
      const context = {
        ...mockContext,
        secrets: { ...mockContext.secrets, LDAP_BIND_PASSWORD: '' }
      };

      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: { displayName: 'Test' }
      };

      await expect(script.invoke(params, context)).rejects.toThrow('LDAP_BIND_PASSWORD secret is required');
    });

    test('should set rejectUnauthorized false when TLS_SKIP_VERIFY is true', async () => {
      const context = {
        ...mockContext,
        environment: { ...mockContext.environment, TLS_SKIP_VERIFY: 'true' }
      };

      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: { displayName: 'Test' }
      };

      await script.invoke(params, context);

      expect(Client).toHaveBeenCalledWith({
        url: 'ldaps://dc.example.com:636',
        timeout: 10000,
        connectTimeout: 10000,
        tlsOptions: { rejectUnauthorized: false }
      });
    });

    test('should set rejectUnauthorized to true for ldaps:// URLs when TLS_SKIP_VERIFY is not set', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: { displayName: 'Test' }
      };

      await script.invoke(params, mockContext);

      expect(Client).toHaveBeenCalledWith({
        url: 'ldaps://dc.example.com:636',
        timeout: 10000,
        connectTimeout: 10000,
        tlsOptions: { rejectUnauthorized: true }
      });
    });

    test('should not include tlsOptions for ldap:// URLs when TLS_SKIP_VERIFY is not set', async () => {
      mockGetBaseURL.mockReturnValue('ldap://dc.example.com:389');

      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: { displayName: 'Test' }
      };

      await script.invoke(params, mockContext);

      expect(Client).toHaveBeenCalledWith({
        url: 'ldap://dc.example.com:389',
        timeout: 10000,
        connectTimeout: 10000
      });
    });

    test('should pass address parameter override via getBaseURL', async () => {
      mockGetBaseURL.mockReturnValue('ldaps://override.example.com:636');

      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: { displayName: 'Test' },
        address: 'ldaps://override.example.com:636'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.address).toBe('ldaps://override.example.com:636');
    });

    test('should call getBaseURL with params and context', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: { displayName: 'Test' }
      };

      await script.invoke(params, mockContext);

      expect(mockGetBaseURL).toHaveBeenCalledWith(params, mockContext);
    });

    test('should pass array attribute values through without double-wrapping', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: {
          otherTelephone: ['+1-555-0100', '+1-555-0101']
        }
      };

      await script.invoke(params, mockContext);

      expect(mockModify).toHaveBeenCalledWith(
        'CN=John Doe,OU=Users,DC=example,DC=com',
        [
          {
            operation: 'replace',
            modification: { type: 'otherTelephone', values: ['+1-555-0100', '+1-555-0101'] }
          }
        ]
      );
    });
  });

  describe('named input parameters', () => {
    test('should map named params to LDAP attribute names without additionalAttributes object', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toEqual(expect.arrayContaining(['givenName', 'sn', 'mail']));
      expect(mockModify).toHaveBeenCalledWith(
        'CN=John Doe,OU=Users,DC=example,DC=com',
        expect.arrayContaining([
          { operation: 'replace', modification: { type: 'givenName', values: ['John'] } },
          { operation: 'replace', modification: { type: 'sn', values: ['Doe'] } },
          { operation: 'replace', modification: { type: 'mail', values: ['john@example.com'] } }
        ])
      );
    });

    test('should merge named params with additionalAttributes object', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        firstName: 'John',
        additionalAttributes: {
          telephoneNumber: '+1-555-0100'
        }
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toEqual(expect.arrayContaining(['telephoneNumber', 'givenName']));
    });

    test('should let named params override conflicting additionalAttributes keys', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        email: 'named@example.com',
        additionalAttributes: {
          mail: 'attributes@example.com'
        }
      };

      await script.invoke(params, mockContext);

      expect(mockModify).toHaveBeenCalledWith(
        'CN=John Doe,OU=Users,DC=example,DC=com',
        [
          { operation: 'replace', modification: { type: 'mail', values: ['named@example.com'] } }
        ]
      );
    });

    test('should map all 9 named params to correct LDAP names', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        samAccountName: 'jdoe',
        userPrincipalName: 'jdoe@example.com',
        firstName: 'John',
        lastName: 'Doe',
        displayName: 'John Doe',
        email: 'john@example.com',
        company: 'Example Corp',
        department: 'Engineering',
        title: 'Engineer'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.attributes).toEqual(expect.arrayContaining([
        'sAMAccountName', 'userPrincipalName', 'givenName', 'sn', 'displayName',
        'mail', 'company', 'department', 'title'
      ]));
    });

    test('should map userPrincipalName to LDAP userPrincipalName', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        userPrincipalName: 'jdoe@example.com'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toContain('userPrincipalName');
      expect(mockModify).toHaveBeenCalledWith(
        'CN=John Doe,OU=Users,DC=example,DC=com',
        [
          { operation: 'replace', modification: { type: 'userPrincipalName', values: ['jdoe@example.com'] } }
        ]
      );
    });

    test('should throw when no named params and no additionalAttributes provided', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        'At least one attribute must be provided'
      );
      expect(mockBind).not.toHaveBeenCalled();
    });

    test('should throw when empty additionalAttributes and no named params provided', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        additionalAttributes: {}
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow(
        'At least one attribute must be provided'
      );
      expect(mockBind).not.toHaveBeenCalled();
    });
  });

  describe('password parameter', () => {
    test('should set unicodePwd as encoded Buffer when password is provided', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        password: 'P@ssw0rd123'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toContain('unicodePwd');

      const modifyCall = mockModify.mock.calls[0];
      const unicodePwdChange = modifyCall[1].find(
        c => c.modification.type === 'unicodePwd'
      );
      expect(unicodePwdChange).toBeDefined();
      expect(unicodePwdChange.operation).toBe('replace');

      const pwdValue = unicodePwdChange.modification.values[0];
      expect(Buffer.isBuffer(pwdValue)).toBe(true);

      const expectedBuffer = Buffer.from('"P@ssw0rd123"', 'utf16le');
      expect(pwdValue).toEqual(expectedBuffer);
    });

    test('should not set unicodePwd when password is omitted', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        firstName: 'John'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.attributes).not.toContain('unicodePwd');
    });
  });

  describe('changePasswordAtNextLogin parameter', () => {
    test('should set pwdLastSet to 0 when changePasswordAtNextLogin is true', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        changePasswordAtNextLogin: true
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.attributes).toContain('pwdLastSet');
      expect(mockModify).toHaveBeenCalledWith(
        'CN=John Doe,OU=Users,DC=example,DC=com',
        [
          { operation: 'replace', modification: { type: 'pwdLastSet', values: ['0'] } }
        ]
      );
    });

    test('should not set pwdLastSet when changePasswordAtNextLogin is false', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        changePasswordAtNextLogin: false,
        firstName: 'John'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.attributes).not.toContain('pwdLastSet');
    });
  });

  describe('missing required parameters', () => {
    test('should throw when userDN is missing', async () => {
      const params = { firstName: 'John' };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('userDN is required');
      expect(mockBind).not.toHaveBeenCalled();
    });
  });

  describe('unbind error handling', () => {
    test('should handle unbind errors gracefully', async () => {
      mockUnbind.mockRejectedValueOnce(new Error('Unbind failed'));

      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        firstName: 'John'
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('success');
      expect(result.modified).toBe(true);
    });

    test('should not mask original error when unbind also fails', async () => {
      mockModify.mockRejectedValueOnce(new Error('Modify operation failed'));
      mockUnbind.mockRejectedValueOnce(new Error('Unbind failed'));

      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        firstName: 'John'
      };

      await expect(script.invoke(params, mockContext)).rejects.toThrow('Modify operation failed');
    });
  });

  describe('dry run', () => {
    test('should return dry_run_completed when dry_run is true', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        firstName: 'John',
        dry_run: true
      };

      const result = await script.invoke(params, mockContext);

      expect(result.status).toBe('dry_run_completed');
      expect(result.userDN).toBe('CN=John Doe,OU=Users,DC=example,DC=com');
      expect(result.modified).toBe(false);
      expect(result.attributes).toContain('givenName');
      expect(mockBind).not.toHaveBeenCalled();
      expect(mockModify).not.toHaveBeenCalled();
    });
  });

  describe('error handler', () => {
    test('should re-throw error and log context', async () => {
      const error = new Error('LDAP connection failed');
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        error
      };

      await expect(script.error(params, mockContext)).rejects.toThrow('LDAP connection failed');
    });
  });

  describe('halt handler', () => {
    test('should return halted status with userDN', async () => {
      const params = {
        userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
        reason: 'timeout'
      };

      const result = await script.halt(params, mockContext);

      expect(result.status).toBe('halted');
      expect(result.userDN).toBe('CN=John Doe,OU=Users,DC=example,DC=com');
      expect(result.reason).toBe('timeout');
      expect(result.halted_at).toBeDefined();
    });

    test('should handle halt without userDN', async () => {
      const params = {
        reason: 'system_shutdown'
      };

      const result = await script.halt(params, mockContext);

      expect(result.status).toBe('halted');
      expect(result.userDN).toBe('unknown');
      expect(result.reason).toBe('system_shutdown');
    });
  });
});
