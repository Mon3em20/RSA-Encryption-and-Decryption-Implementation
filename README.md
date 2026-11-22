# RSA Encryption and Decryption (Java, educational)

A short educational Java implementation of textbook RSA in `src/RSA.java`, using `java.math.BigInteger`.

## What it does

- Asks for a key size in bits (minimum 256) and generates two random primes with `SecureRandom`.
- Computes `n = p*q` and uses public exponent 65537 (adjusted upward if it is not coprime to phi).
- Reads `message.txt`, encrypts the whole message as one big integer, writes the result to `encryptedRSA.txt`, then reads it back, decrypts it and writes `decryptedRSA.txt`.
- Prints the keys, message and ciphertext to the console.

## Educational limitations (not for real use)

- **Textbook RSA:** no padding (such as OAEP). Encryption is deterministic and malleable.
- **Single block:** the whole message is one integer, so the message must be smaller than `n`; longer messages are not supported.
- **Small keys:** the program accepts keys as small as 256 bits, which are not secure. Modern guidance recommends at least 2048 bits.
- **Key handling:** the private key is printed to the console and not stored securely.

Use an established library and an approved padding scheme for any real application.

## Repository notes

`encyptedRSA.txt` (misspelled) and `encryptedRSA.txt` are sample outputs; `out/` contains compiled class files and `untitled.iml` is an IDE file.
