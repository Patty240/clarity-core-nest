# CoreNest

A decentralized system for managing personal data on the Stacks blockchain. CoreNest allows users to:

- Store encrypted personal data references
- Control access to their data
- Grant and revoke access permissions
- Track data access history
- Manage encryption keys for end-to-end encryption

## Features

- Secure data storage using principal-based ownership
- Granular access control mechanisms
- Permission management system
- Activity logging
- Data reference encryption
- End-to-end encryption key management
- Per-user encrypted key distribution

## Security

All sensitive data references are encrypted before being stored on-chain. The actual data should be stored off-chain with only encrypted references stored in the contract.

### Encryption Key Management

The system now supports end-to-end encryption with the following features:
- Store encryption key hashes for data verification
- Securely share encryption keys with authorized users
- Keys are encrypted specifically for each granted user
- Automatic key revocation during access removal
