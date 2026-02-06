import { Client } from 'ldapts';
import { getBaseURL } from '@sgnl-actions/utils';

const UAC_ENABLED = '512';
const UAC_DISABLED = '514';

const PARAM_TO_LDAP = {
  samAccountName: 'sAMAccountName',
  userPrincipalName: 'userPrincipalName',
  firstName: 'givenName',
  lastName: 'sn',
  displayName: 'displayName',
  email: 'mail',
  company: 'company',
  department: 'department',
  title: 'title'
};

function encodePassword(password) {
  const quotedPassword = `"${password}"`;
  return Buffer.from(quotedPassword, 'utf16le');
}

function buildAttributes(params) {
  const merged = { ...(params.additionalAttributes || {}) };
  for (const [param, ldapName] of Object.entries(PARAM_TO_LDAP)) {
    if (params[param] !== undefined) {
      merged[ldapName] = params[param];
    }
  }
  return merged;
}

async function updateUserAttributes(userDN, attributes, client) {
  const changes = Object.entries(attributes).map(([key, value]) => ({
    operation: 'replace',
    modification: {
      [key]: Array.isArray(value) ? value : [value]
    }
  }));

  await client.modify(userDN, changes);
}

export default {
  invoke: async (params, context) => {
    const { userDN, dry_run = false } = params;
    const attributes = buildAttributes(params);

    if (params.enabled !== undefined) {
      attributes.userAccountControl = params.enabled ? UAC_ENABLED : UAC_DISABLED;
    }
    if (params.password) {
      attributes.unicodePwd = encodePassword(params.password);
    }
    if (params.changePasswordAtNextLogin) {
      attributes.pwdLastSet = '0';
    }

    if (!attributes || typeof attributes !== 'object' || Object.keys(attributes).length === 0) {
      throw new Error('At least one attribute must be provided');
    }

    if (dry_run) {
      console.log('DRY RUN: No changes will be made to Active Directory');
      return {
        status: 'dry_run_completed',
        userDN,
        modified: false,
        attributes: Object.keys(attributes)
      };
    }

    const address = getBaseURL(params, context);
    const username = context.secrets.LDAP_BIND_DN;
    const password = context.secrets.LDAP_BIND_PASSWORD;

    if (!username) {
      throw new Error('LDAP_BIND_DN secret is required');
    }
    if (!password) {
      throw new Error('LDAP_BIND_PASSWORD secret is required');
    }

    const tlsOptions = {};
    if (context.environment?.TLS_SKIP_VERIFY === 'true') {
      tlsOptions.rejectUnauthorized = false;
    }

    const client = new Client({
      url: address,
      tlsOptions
    });

    try {
      await client.bind(username, password);
      await updateUserAttributes(userDN, attributes, client);

      return {
        status: 'success',
        userDN,
        modified: true,
        attributes: Object.keys(attributes),
        address
      };
    } finally {
      await client.unbind();
    }
  },

  error: async (params, _context) => {
    const { error, userDN } = params;
    console.error(`Failed to update AD user ${userDN}: ${error.message}`);

    const errorMessage = error.message.toLowerCase();

    // Authentication errors (fatal - don't retry)
    if (errorMessage.includes('invalid credentials') ||
        errorMessage.includes('authentication') ||
        errorMessage.includes('bind failed')) {
      console.error('Authentication failed - check LDAP_BIND_DN and LDAP_BIND_PASSWORD');
      throw new Error(`LDAP authentication failed: ${error.message}`);
    }

    // Connection errors (retryable)
    if (errorMessage.includes('connection') ||
        errorMessage.includes('timeout') ||
        errorMessage.includes('econnrefused')) {
      console.error('Connection error - may be transient, framework will retry');
      throw error;
    }

    // User not found (fatal - don't retry)
    if (errorMessage.includes('no such object') ||
        errorMessage.includes('not found')) {
      console.error('User not found - check userDN');
      throw new Error(`User not found: ${error.message}`);
    }

    // Constraint violations (fatal - don't retry)
    if (errorMessage.includes('constraint violation') ||
        errorMessage.includes('invalid syntax')) {
      console.error('Data validation error - check input parameters');
      throw new Error(`Invalid attribute data: ${error.message}`);
    }

    // Insufficient permissions (fatal - don't retry)
    if (errorMessage.includes('insufficient access') ||
        errorMessage.includes('permission denied')) {
      console.error('Insufficient permissions - check service account privileges');
      throw new Error(`Insufficient LDAP permissions: ${error.message}`);
    }

    // Unknown error - re-throw for framework retry
    console.error('Unknown error occurred, allowing framework to retry');
    throw error;
  },

  halt: async (params, _context) => {
    const { reason, userDN } = params;
    return {
      status: 'halted',
      userDN: userDN || 'unknown',
      reason,
      halted_at: new Date().toISOString()
    };
  }
};
