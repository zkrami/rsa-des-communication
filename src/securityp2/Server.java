/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityp2;

import java.net.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import securityp2.Utilities.Protocol;
import sun.net.ConnectionResetException;

/**
 *
 * @author Rami
 */
public class Server {

    ServerSocket socket;
    Socket client;
    String publicKey;
    byte[] sessionKey;

    public Key factorPublicKey() throws Exception {
        this.publicKey = this.publicKey.replace("-----BEGIN PUBLIC KEY-----", "");
        this.publicKey = this.publicKey.replace("-----END PUBLIC KEY-----", "");
        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(this.publicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public byte[] encryptRSA(String str) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.ENCRYPT_MODE, this.factorPublicKey());
        return rsa.doFinal(str.getBytes());
    }

    public Key factorPrivateKey() throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get("private.der")));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public byte[] decryptRSA(byte[] bytes) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, this.factorPrivateKey());
        return rsa.doFinal(bytes);
    }

    public Server() throws IOException {
        socket = new ServerSocket(2000);
        this.publicKey = String.join("", Files.readAllLines(Paths.get("public.pem")));
    }

    public void open() throws IOException {
        System.out.println("Waiting ... ");
        this.client = this.socket.accept();
        System.out.println("Client connected");
    }

    public byte[] recieve() throws Exception {
        try {

            ObjectInputStream reader = new ObjectInputStream(this.client.getInputStream());
            int bytesToRecieve = reader.readInt();
            byte[] buff = new byte[bytesToRecieve];
            reader.read(buff);
            return buff;

        } catch (Exception ex) {
            System.err.print("Couldn't recieve the message ");
            throw ex;
        }
    }

    public String recieveMessage() throws Exception {
        return new String(this.recieve());
    }

    public void send(byte[] bytes) throws Exception {

        ObjectOutputStream writer = new ObjectOutputStream(this.client.getOutputStream());
        writer.writeInt(bytes.length);
        writer.write(bytes);
        writer.flush();
    }

    DESCipher cipher;

    public byte[] decrypt(byte[] bytes) {
        return cipher.decrypt(bytes);
    }

    public byte[] encrypt(byte[] bytes) {
        return cipher.encrypt(bytes);
    }

    public void invalidSession() {
        this.sessionKey = null;
        this.cipher = null;
    }

    public void sendEncryptedMessage(String str) throws Exception {
        if (this.sessionKey == null) {
            throw new Exception("Session is not valid");
        }

        this.send(this.encrypt(str.getBytes()));
    }

    public String recieveEncryptedMessage() throws Exception {
        if (this.sessionKey == null) {
            throw new Exception("Session is not valid");
        }

        return new String(this.decrypt(this.recieve()));
    }

    public void sendMessage(String message) throws Exception {
        try {
            this.send(message.getBytes());
        } catch (Exception ex) {
            System.err.println("Couldn't send the message");
            throw ex;
        }
    }

    public static void printArray(byte[] arr) {
        System.out.println(" ");
        for (int i = 0; i < arr.length; i++) {
            System.out.print(arr[i]);
            System.out.print(" ");
        }
        System.out.println(" ");
    }

    /**
     * Wait for the client to send a "Hello" message. And Send the public Key.
     *
     */
    public void initSession() throws Exception {

        try {
            // recieve hello 
            this.sendMessage(this.publicKey);

            byte[] encryptedSesssionKey = this.recieve();
            this.sessionKey = this.decryptRSA(encryptedSesssionKey);
            this.printArray(sessionKey);
            this.cipher = new DESCipher(this.sessionKey);
            // send acknowledgement message 
            this.sendProtocolCode(Protocol.ACK);

        } catch (Exception ex) {
            System.err.println("Couldn't initiate the session");
            throw ex;
        }

    }

    /**
     * Generate server public and private keys using RSA.
     */
    public void initKeys() throws Exception {
        // Generate private/public key 
        if (this.hasKeys()) {
            return;
        }
        try {
            System.out.println("Generating server RSA keys");
            Utilities.command("openssl genrsa -out key.pem 2048");
            System.out.println("Keys generated succefully");
            System.out.println("Extracting the public key");
            Utilities.command("openssl rsa -in key.pem -outform PEM -pubout -out public.pem");

            Utilities.command("openssl pkcs8 -topk8 -inform PEM -outform DER -in key.pem -out private.der -nocrypt");

        } catch (Exception ex) {
            System.err.print("Couldn't generte keys");
            throw ex;
        }

    }

    public boolean hasKeys() {
        File f = new File("key.pem");
        return f.exists();
    }

    public void sendProtocolCode(Utilities.Protocol code) throws Exception {
        ObjectOutputStream writer = new ObjectOutputStream(this.client.getOutputStream());
        writer.writeInt(code.getValue());
        writer.flush();
    }

    public Protocol recieveProtocolCode() throws Exception {
        ObjectInputStream reader = new ObjectInputStream(this.client.getInputStream());
        int code = reader.readInt();
        if (code == Utilities.Protocol.InitSession.getValue()) {
            return Utilities.Protocol.InitSession;
        }
        if (code == Utilities.Protocol.Message.getValue()) {
            return Utilities.Protocol.Message;
        }
        if (code == Utilities.Protocol.ACK.getValue()) {
            return Utilities.Protocol.ACK;
        }

        return Utilities.Protocol.InvalidSession;
    }

    public void close() throws Exception {
        this.socket.close();
    }

    public static void main(String[] args) {
        // TODO code application logic here

        try {
            Server s = new Server();

            //s.initKeys();
            s.open();
            while (true) {

                Protocol code = s.recieveProtocolCode();
                switch (code) {
                    case InitSession: {
                        System.out.println("Initiating session");
                        s.initSession();
                        break;
                    }
                    case InvalidSession: {
                        System.out.println("Invalidating session");
                        s.invalidSession();
                        break;
                    }
                    case Message: {
                        System.out.println("Recieving message from the client:");
                        String message = s.recieveEncryptedMessage();
                        System.out.println(message);
                        System.out.println("Sending the message back to the client");
                        s.sendEncryptedMessage("Hola my lovely client here is what I got from you:\n" + message);
                        break;
                    }
                }

            }

        } catch (Exception ex) {
            if (ex instanceof EOFException) {
                System.out.print("Client closed connection \n");
            } else {
                System.out.println(ex);
                System.out.print("couldn't connect");
            }

        }
    }

}
