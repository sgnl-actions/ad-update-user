#!/usr/bin/env node

/**
 * Development runner for testing scripts locally
 */

import script from '../src/script.mjs';

const mockContext = {
  environment: {
    ADDRESS: 'ldaps://dc.example.com:636',
    // TLS_SKIP_VERIFY: 'true',  // Uncomment to skip TLS certificate verification
  },
  secrets: {
    LDAP_BIND_DN: 'CN=admin,DC=example,DC=com',
    LDAP_BIND_PASSWORD: 'admin-password',
  },
  outputs: {},
  partial_results: {},
  current_step: 'start',
};

const mockParams = {
  userDN: 'CN=John Doe,OU=Users,DC=example,DC=com',
  firstName: 'John',
  lastName: 'Doe',
  email: 'john.doe@example.com',
  department: 'Engineering',
  title: 'Software Engineer',
  additionalAttributes: {
    telephoneNumber: '+1-555-0100',
  },
  dry_run: true,  // Set to false to actually update the user
};

async function runDev() {
  console.log('Running job script in development mode...\n');

  console.log('Parameters:', JSON.stringify(mockParams, null, 2));
  console.log('Context:', JSON.stringify(mockContext, null, 2));
  console.log('\n' + '='.repeat(50) + '\n');

  try {
    const result = await script.invoke(mockParams, mockContext);
    console.log('\n' + '='.repeat(50));
    console.log('Job completed successfully!');
    console.log('Result:', JSON.stringify(result, null, 2));
  } catch (error) {
    console.log('\n' + '='.repeat(50));
    console.error('Job failed:', error.message);

    if (script.error) {
      console.log('\nAttempting error recovery...');
      try {
        const recovery = await script.error({...mockParams, error}, mockContext);
        console.log('Recovery successful!');
        console.log('Recovery result:', JSON.stringify(recovery, null, 2));
      } catch (recoveryError) {
        console.error('Recovery failed:', recoveryError.message);
      }
    }
  }
}

runDev().catch(console.error);
