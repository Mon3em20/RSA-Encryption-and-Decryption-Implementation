import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class RSA {
    private BigInteger p, q, n, phi, e, d;

    public RSA(int keySize) {
        SecureRandom random = new SecureRandom();
        int bitLength = keySize / 2;
        p = BigInteger.probablePrime(bitLength, random);
        q = BigInteger.probablePrime(bitLength, random);
        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.valueOf(65537); //public key
        while (phi.gcd(e).compareTo(BigInteger.ONE) != 0) {
            e = e.add(BigInteger.ONE);
        }
        d = e.modInverse(phi); //private key
    }

    public BigInteger encrypt(byte[] messageBytes) {
        BigInteger message = new BigInteger(1, messageBytes);
        return message.modPow(e, n);
    }

    public byte[] decrypt(BigInteger ciphertext) {
        BigInteger decrypted = ciphertext.modPow(d, n);
        byte[] decryptedBytes = decrypted.toByteArray();
        if (decryptedBytes[0] == 0) {
            decryptedBytes = Arrays.copyOfRange(decryptedBytes, 1, decryptedBytes.length);
        }
        return decryptedBytes;
    }

    public static void main(String[] args) throws IOException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter Size:");
        int keySize = scanner.nextInt();
        while (keySize < 256) {
            System.out.println("n must be greater than or equals 256");
            keySize = scanner.nextInt();
        }

        RSA rsa = new RSA(keySize);

        // Encrypt message.txt
        Path messagePath = Paths.get("message.txt");
        byte[] messageBytes = Files.readAllBytes(messagePath);
        BigInteger ciphertext = rsa.encrypt(messageBytes);

        // Write encryptedRSA.txt
        Path encryptedPath = Paths.get("encryptedRSA.txt");
        String encryptedPlain = new String(ciphertext.toByteArray(), StandardCharsets.ISO_8859_1);
        String encryptedContent = "Encrypted Cipher in plaintext: " + encryptedPlain + "\n"
                + "Encrypted Cipher in big integer: " + ciphertext.toString();
        Files.write(encryptedPath, encryptedContent.getBytes(StandardCharsets.UTF_8));

        // Decrypt
        String encryptedFileContent = new String(Files.readAllBytes(encryptedPath), StandardCharsets.UTF_8);
        String[] lines = encryptedFileContent.split("\n");
        String bigIntLine = lines[1];
        BigInteger ciphertextFromFile = new BigInteger(bigIntLine.split(": ")[1]);
        byte[] decryptedBytes = rsa.decrypt(ciphertextFromFile);

        // Write decryptedRSA.txt
        Path decryptedPath = Paths.get("decryptedRSA.txt");
        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
        String decryptedContent = "Decrypted Message in plaintext: " + decryptedText + "\n"
                + "Decrypted Message in big integer: " + new BigInteger(1, decryptedBytes).toString();
        Files.write(decryptedPath, decryptedContent.getBytes(StandardCharsets.UTF_8));

        // Output keys and messages as per sample
        System.out.println("The generated public key in plaintext: " + rsa.fromBigIntegerToString(rsa.e));
        System.out.println("The generated public key in big integer: " + rsa.e);
        System.out.println("The generated private key in plaintext: " + rsa.fromBigIntegerToString(rsa.d));
        System.out.println("The generated private key in big integer: " + rsa.d);
        System.out.println("Message in plaintext: " + new String(messageBytes, StandardCharsets.UTF_8));
        System.out.println("Message in big integer: " + new BigInteger(1, messageBytes));
        System.out.println("Encrypted Cipher in plaintext: " + encryptedPlain);
        System.out.println("Encrypted Cipher in big integer: " + ciphertext);
        System.out.println("Decrypted Message in plaintext: " + decryptedText);
        System.out.println("Decrypted Message in big integer: " + new BigInteger(1, decryptedBytes));
    }

    private String fromBigIntegerToString(BigInteger num) {
        return new String(num.toByteArray(), StandardCharsets.ISO_8859_1);
    }
}