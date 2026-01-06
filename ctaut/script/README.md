Here is the information about AUT (Abelian User Token) protocol.

### Overview
AutScript is embed in TxMemo field of an Abelian transfer transaction, 
and is interpreted with the following formats:

1. Registration Script, declares a new AutInstance, and as the result, a corresponding 
AutMetadata record is initialized, including the following fields:
   - version
     - uint32, initialized to 1
   - autIdentifier, used as a unique identifier for the instance
     - a Hash (aka. [32]byte)
     - set to be the TxId of the Abelian Tx where the Registration Script is embed in
     - CAN'T be changed anymore
   - autSymbol, used as a symbol visible to the user
     - a byte array with max length (64)
     - [#TODO] CAN'T be changed anymore
   - token unit, including 
     - common units, a byte array with max length (20)
       - [#TODO] CAN'T be changed anymore
     - minimum units, a byte array with max length (20)
       - [#TODO] CAN'T be changed anymore
     - the conversion ratio between common units and minimum units 
       - an integer range in (0, $2^{51}$ -1) [#TODO inclusive or not for upper limit?]
       - [#TODO] CAN'T be changed anymore
   - total planned issuance amount, counting in minimum units
     - an integer range in (0, $2^{51}$ -1) [#TODO inclusive or not for upper limit?]
     - could be changed with subsequent re-registration scripts
   - AUT memo, used as a note for instance
       - a byte array with max length (1024)
   - issuers, used to auth for subsequent operations on instances (mint/re-register)
     - an array with length N distinct pseudonymous (coin-)address (193-byte)
     - N MUST less than or equal to 100
   - mint threshold, 
     - an integer $t$ such that $t \leq N$
     - imply that a valid Mint Script need provide a proof that at least $t$-out-of-the-$N$ issuers authenticate the operation.   
   - re-registration threshold
     - an integer, less than or equal to N
   - expiry block height
     - 32-bit signed integer
     - all root coins will expire after this height
     - next re-registration MUST occur before this height   
   - number of root coins, the root coins would be one-time access token for subsequent operations on instances
     - each root coin MUST belongs to an issuer
2. mint, it would consume a few root coins, and generate a few coins (called aut coins) as token to transfer value, including
the following fields:
   - identifier, specifies which instance is to be operated
   - vin, the amount (counting in minimum units) would be issuance in this minting
     - an integer range in (0, $2^{51}$ -1) [#TODO inclusive or not for upper limit?]
   - number of root coins, consumed by this minting
     - the number of issuers participating in this minting MUST meet the issuance thresholds
   - number of aut coins
     - each coin would carry some amounts
     - the amount for coin may be hidden or public
       - the hidden amount, would be an value script
       - the public amount, would be an integer
   - the balance proof would be appended to Abelian transaction and referred as witness
3. re-register, it would consume a few root coins, as the result, the metadata of specified instance would be updated, 
including the following fields:
   - identifier, specifies which instance is to be operated
   - NEW total planned issuance, counting in minimum units
       - an integer range in (0, $2^{51}$ -1) [#TODO inclusive or not for upper limit?]
       - CAN'T be less than the amount already minted
   - NEW AUT memo, used as a note
       - a byte array with max length
   - NEW issuers, used to auth for subsequent operations on instances (mint/re-register)
       - an array of public key
       - length N
   - NEW issuance threshold,
       - an integer, less than or equal to N
   - NEW re-registration threshold
       - an integer, less than or equal to N
   - expiry block height, next re-registration MUST occur before this height
   - number of root coins as inputs, consumed by this re-registration, **all root coins will expire anyway whether they are spent or not**
       - the number of issuers participating in this re-registration must meet the re-registration threshold
   - number of root coins as outputs, the root coins would be one-time access token for subsequent operations on instances
       - each root coin MUST belong to an NEW issuer
4. transfer, it would consume aut coins and generate a few aut coins
    - identifier, specifies which instance is to be operated
    - number of aut coins, consumed by this transfer
    - number of aut coins
        - each coin would carry some amounts
        - the amount for coin may be hidden or public
            - the hidden amount, would be a value script
            - the public amount, would be an integer
    - the balance proof would be appended to Abelian transaction and referred as witness
5. burn, it would consume aut coins and generate a few aut coins
    - identifier, specifies which instance is to be operated
    - number of aut coins, consumed by this burn
    - number of aut coins
        - each coin would carry some amounts
        - the amount for coin may be hidden or public
            - the hidden amount, would be a value script
            - the public amount, would be an integer
        - the first coin would be marked burned
    - the balance proof would be appended to Abelian transaction and referred as witness

### Implementation Notes
- For `IssuerTokens`, using SHA3-512, define a standalone hash in AUT. Hash(CoinAddress)?
- 
