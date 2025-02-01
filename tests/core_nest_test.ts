import {
  Clarinet,
  Tx,
  Chain,
  Account,
  types
} from 'https://deno.land/x/clarinet@v1.0.0/index.ts';
import { assertEquals } from 'https://deno.land/std@0.90.0/testing/asserts.ts';

Clarinet.test({
    name: "Ensure users can store and manage data access with encryption keys",
    async fn(chain: Chain, accounts: Map<string, Account>) {
        const deployer = accounts.get('deployer')!;
        const user1 = accounts.get('wallet_1')!;
        const user2 = accounts.get('wallet_2')!;
        
        // Test storing data with key hash
        let block = chain.mineBlock([
            Tx.contractCall('core-nest', 'store-data',
                [
                    types.utf8("encrypted-data-reference-1"),
                    types.some(types.utf8("key-hash-1"))
                ],
                user1.address
            )
        ]);
        block.receipts[0].result.expectOk().expectUint(1);
        
        // Test granting access with encrypted key
        block = chain.mineBlock([
            Tx.contractCall('core-nest', 'grant-access',
                [
                    types.uint(1),
                    types.principal(user2.address),
                    types.some(types.utf8("encrypted-key-for-user2"))
                ],
                user1.address
            )
        ]);
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Test accessing data and getting encryption key
        block = chain.mineBlock([
            Tx.contractCall('core-nest', 'access-data',
                [types.uint(1)],
                user2.address
            )
        ]);
        const accessResult = block.receipts[0].result.expectOk();
        assertEquals(accessResult['reference'], types.utf8("encrypted-data-reference-1"));
        assertEquals(accessResult['key'], types.some(types.utf8("encrypted-key-for-user2")));
        
        // Test revoking access
        block = chain.mineBlock([
            Tx.contractCall('core-nest', 'revoke-access',
                [types.uint(1), types.principal(user2.address)],
                user1.address
            )
        ]);
        block.receipts[0].result.expectOk().expectBool(true);
        
        // Verify key hash
        block = chain.mineBlock([
            Tx.contractCall('core-nest', 'get-key-hash',
                [types.uint(1)],
                user1.address
            )
        ]);
        block.receipts[0].result.expectOk().expectSome().expectUtf8("key-hash-1");
    }
});
