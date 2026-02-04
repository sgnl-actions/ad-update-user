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
    const { userDN } = params;
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

    const address = getBaseURL(params, context);
    const username = context.secrets.BASIC_USERNAME;
    const password = context.secrets.BASIC_PASSWORD;

    if (!username) {
      throw new Error('BASIC_USERNAME secret is required');
    }
    if (!password) {
      throw new Error('BASIC_PASSWORD secret is required');
    }

    const tlsOptions = {};
    if (context.env.TLS_SKIP_VERIFY === 'true') {
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
    console.error(`Error updating user ${userDN}: ${error.message}`);
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
