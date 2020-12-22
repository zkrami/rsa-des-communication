/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityp2;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import securityp2.Utilities.Protocol;

/**
 *
 * @author Rami
 */
public class Client {

    Socket socket;
    String publicKey;
    String sessionKey = "n wqeasd asd asd ";

    public Client(String host) throws IOException {

        this.socket = new Socket(host, 2000);
    }

    /**
     * Recieve a message from the server
     */
    public byte[] recieve() throws Exception {
        try {

            ObjectInputStream reader = new ObjectInputStream(this.socket.getInputStream());
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

        ObjectOutputStream writer = new ObjectOutputStream(this.socket.getOutputStream());
        writer.writeInt(bytes.length);
        writer.write(bytes);
        writer.flush();
    }

    public void sendMessage(String message) throws Exception {
        try {
            this.send(message.getBytes());
        } catch (Exception ex) {
            System.err.println("Couldn't send the message");
            throw ex;
        }
    }

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

    /**
     * Encrypt 4 bytes
     */
    public byte[] encryptDes(byte[] bytes) {
        return bytes;
    }

    /*
    * Decrypt 4 bytes 
     */
    public byte[] decryptDes(byte[] bytes) {
        return bytes;
    }

    public byte[] decrypt(byte[] bytes) {

        byte[] result = new byte[bytes.length];

        for (int i = 0; i < bytes.length; i += 4) {
            byte[] block = Arrays.copyOfRange(bytes, i, i + 4);
            block = decryptDes(block);
            for (int j = 0; j < 4; j++) {
                result[i + j] = block[j];
            }
        }
        return result;

    }

    public byte[] encrypt(byte[] bytes) {

        byte[] result = new byte[bytes.length + bytes.length % 4];
        // encrypt each block 
        for (int i = 0; i < bytes.length; i += 4) {
            byte[] block = Arrays.copyOfRange(bytes, i, i + 4); // if copy range is out of the original range the method appends the copied arrays with 0 
            block = encryptDes(block);
            for (int j = 0; j < 4; j++) {
                result[i + j] = block[j];
            }

        }
        return result;

    }
    
    public void sendEncryptedMessage(String str) throws Exception {
        if (this.sessionKey == null) {
            throw new Exception("Session is not valid");
        }

        this.send(this.encryptDes(str.getBytes()));
    }

    public String recieveEncryptedMessage() throws Exception {
        if (this.sessionKey == null) {
            throw new Exception("Session is not valid");
        }

        return new String(this.decryptDes(this.recieve()));
    }

    public void sendProtocolCode(Protocol code) throws Exception {
        ObjectOutputStream writer = new ObjectOutputStream(this.socket.getOutputStream());
        writer.writeInt(code.getValue());
        writer.flush();
    }

      public Protocol recieveProtocolCode() throws Exception {
        ObjectInputStream reader = new ObjectInputStream(this.socket.getInputStream());
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


    public void initSession() throws Exception {
        try {
            this.sendProtocolCode(Protocol.InitSession);
            this.publicKey = this.recieveMessage();
            this.send(this.encryptRSA(this.sessionKey));
            if(this.recieveProtocolCode() != Protocol.ACK){
                throw new Exception("Server didn't send Acknowledgement message"); 
            }

        } catch (Exception ex) {
            System.err.println("Couldn't initiate the session");
            throw ex;
        }

    }
    public  void invalidSession() throws Exception{
        this.sessionKey = null; 
        this.sendProtocolCode(Protocol.InvalidSession);
    }

    public static void main(String args[]) {

        try {
            Client client = new Client("127.0.0.1");
            System.out.println("Connected to server");
            client.initSession();
            
            
            // sending message and recieving reply 
            System.out.println("Sending message and recieving reply from the server");
            client.sendProtocolCode(Protocol.Message);
            client.sendEncryptedMessage("Message 1");
            String message = client.recieveEncryptedMessage();
            System.out.println("Message recieved from server");
            System.out.println(message); 
            
            client.invalidSession();
            

        } catch (Exception ex) {
            System.err.print(ex);
        }
    }
}
