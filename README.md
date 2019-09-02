# Elliptic Curve Digital Signature Algorithm (ECDSA)

Program written to implement ECDSA (Elliptic Curve Digital Signature Algorithm) algorithm.

It is possible to sign a message with private key generated in [GoLang program](https://github.com/jushua720/chaincode/blob/master/votingCC/utils/access/access.go). 

R, S values extracted from the signature and X, Y coordinates of public key received from the given private key can be used to verify signature in GoLang program [which is implemented in voting chaincode - ssilka] 

&nbsp; 

## Detailed Information on Implemented Functions in ecdsa.java


| Function                  | Description   |
| :-----                    | :-----        | 
| generateKeys              | Generates ECDSA public and private key           | 
| getPrivateKey             | Given string returns PrivateKey ( *java.security.PrivateKey* ) |
| getPublicKeyFromPrivate   | Given PrivateKey ( *java.security.PrivateKey* ) returns PublicKey( *java.security.PublicKey* ) |
| pubKeyToString            | Converts PublicKey( *java.security.PublicKey* ) to string | 
| privKeyToString           | Converts PrivateKey( *java.security.PrivateKey* ) to string | 
| getXYUsingPrivateKey      | Given private key as string returns X, Y ecdsa public key point coordinates |
| getPublicKeyFromXY        | Construct *java.security.PublicKey* using X, Y coordinates  |
| signMessage               | Given PrivateKey( *java.security.PrivateKey* ) returns message signed wih the given key. <br> Later signature can be verified with the public key. <br> Compatible with keys generated in GoLang program |
| signMessage               | Given private key ( *string* ) returns message signed wih the given key | 
| getRFromSignature         | Given signature ( *byte[]* ) returns R value ( *Biginteger* ) | 
| getSFromSignature         | Given signature ( *byte[]* ) returns S value ( *Biginteger* ) |
| hashString                | Returns sha-256 string hash |
| verifySignature           | Verifies signature ( *string* ) with public key ( *string* ) | 
| encryptMessage            | Encrypts message ( *string* ) with public key ( *string* ) | 
| decryptMessage            | Descrypt encrypted message ( *string* ) with private key ( *string* )  |
| b58encode                 | Base58 string encodong |
| b58decode                 | Base58 string decoding | 
| convertToBigInteger       | Given string value returns BigInteger value | 
