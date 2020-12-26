package securityp2;

import java.util.Arrays;
import java.util.Random;

/**
 *
 * @author Rami
 */
public class DESCipher {

    // 3Des Cipher 
    byte[][] keys;
    DES[] ciphers = new DES[3];

    // 168 bits key (21 byte) 
    public DESCipher(byte[] key) {
        this.keys = new byte[3][];
        this.keys[0] = Arrays.copyOfRange(key, 0, 7);
        this.keys[1] = Arrays.copyOfRange(key, 7, 14);
        this.keys[2] = Arrays.copyOfRange(key, 14, 21);
        for (int i = 0; i < 3; i++) {
            ciphers[i] = new DES(keys[i]);
        }
    }

    public byte[] encrypt(byte[] message) {
        /*
        1. Chiffrer avec k1
        2. Déchiffrer avec k2
        3. Chiffrer avec k3
         */
        return ciphers[2].encrypt(ciphers[1].decrypt(ciphers[0].encrypt(message)));
    }

    public byte[] decrypt(byte[] message) {
        return ciphers[0].decrypt(ciphers[1].encrypt(ciphers[2].decrypt(message)));

    }

    public static void main(String[] args) {

        byte[] key = new byte[21];
        new Random().nextBytes(key);
        byte[] message = ("Message 1").getBytes();

        DESCipher d = new DESCipher(key);

        byte[] e = d.encrypt(message);

        byte[] dd = d.decrypt(e);

        System.out.println("");
        for (int i = 0; i < e.length; i++) {
            System.out.print(e[i]);
            System.out.print(" ");
        }
        System.out.println("");
        for (int i = 0; i < dd.length; i++) {
            System.out.print(dd[i]);
            System.out.print(" ");
        }
        System.out.println("");
        for (int i = 0; i < message.length; i++) {
            System.out.print(message[i]);
            System.out.print(" ");
        }
        System.out.println("");

        System.out.println(Arrays.equals(message, dd));
        System.out.println("");
        System.out.println(new String(dd));
        System.out.println("");
    }

}
