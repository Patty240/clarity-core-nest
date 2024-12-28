import {
  Clarinet,
  Tx,
  Chain,
  Account,
  types
} from 'https://deno.land/x/clarinet@v1.0.0/index.ts';
import { assertEquals } from 'https://deno.land/std@0.90.0/testing/asserts.ts';

Clarinet.test({
    name: "Ensure users can store and manage data access",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        const user1 = accounts.get('wallet_1')!;
        const user2 = accounts.get('wallet_2')!;
        
        // Test storing data
        let block = chain.mineBlock([
            Tx.contractCall('core-nest', 'store-data',
                [types.utf8("encrypted-data-reference-1")],
                user1.address
            )
        ]);
        block.receipts[0].result.expectOk().expectUint(1);
        
        // Test granting access
        block = chain.mineBlock([
            Tx.contractCall('core-nest', 'grant-access',
                [types.uint(1), types.principal(user2.address)],
                user1.address
            )
        ]);
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Test accessing data
        block = chain.mineBlock([
            Tx.contractCall('core-nest', 'access-data',
                [types.uint(1)],
                user2.address
            )
        ]);
        block.receipts[0].result.expectOk().expectUtf8("encrypted-data-reference-1");
        
        // Test revoking access
        block = chain.mineBlock([
            Tx.contractCall('core-nest', 'revoke-access',
                [types.uint(1), types.principal(user2.address)],
                user1.address
            )
        ]);
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Test access after revocation
        block = chain.mineBlock([
            Tx.contractCall('core-nest', 'access-data',
                [types.uint(1)],
                user2.address
            )
        ]);
        block.receipts[0].result.expectErr().expectUint(101); // err-no-permission
    }
});

Clarinet.test({
    name: "Check access logs are properly maintained",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const user1 = accounts.get('wallet_1')!;
        const user2 = accounts.get('wallet_2')!;
        
        // Store data and grant access
        let block = chain.mineBlock([
            Tx.contractCall('core-nest', 'store-data',
                [types.utf8("encrypted-data-reference-2")],
                user1.address
            ),
            Tx.contractCall('core-nest', 'grant-access',
                [types.uint(1), types.principal(user2.address)],
                user1.address
            )
        ]);
        
        // Access data multiple times
        block = chain.mineBlock([
            Tx.contractCall('core-nest', 'access-data',
                [types.uint(1)],
                user2.address
            ),
            Tx.contractCall('core-nest', 'access-data',
                [types.uint(1)],
                user2.address
            )
        ]);
        
        // Check access logs
        block = chain.mineBlock([
            Tx.contractCall('core-nest', 'get-data-access-log',
                [types.uint(1), types.principal(user2.address)],
                user1.address
            )
        ]);
        
        const logResult = block.receipts[0].result.expectOk().expectSome();
        assertEquals(logResult['access-count'], types.uint(2));
    }
});