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

/**
 *
 * @author Rami
 */
public class Server {

    ServerSocket socket;
    Socket client;
    String publicKey;

    public Server() throws IOException {
        socket = new ServerSocket(2000);
    }

    public void open() throws IOException {
        System.out.println("Waiting ... ");
        this.client = this.socket.accept();
        System.out.println("Client connected");
    }

    /*
    *    Send message to the client 
     */
    public void send(String message) {
        try {
            OutputStream out = this.client.getOutputStream();
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
            writer.write(message);
            writer.close();
        } catch (Exception ex) {

        }
    }

    /**
     * Recieve a message from the client
     */
    public String recieve() throws Exception {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(this.client.getInputStream()));
            StringBuilder builder = new StringBuilder();
            String inputLine;
            while ((inputLine = reader.readLine()) != null) {
                builder.append(inputLine);
            }
            String message = builder.toString();
            return message;
        } catch (Exception ex) {
            throw new Exception("Couldn't recieve the message ");
        }
    }

    /**
     * Wait for the client to send a "Hello" message. And Send the public Key.
     *
     */
    public void initSession() throws Exception {

        try {
            System.out.println("Receiving message from the client");
            String message = this.recieve();
            System.out.println("Message received");
            System.out.println(message);
            this.publicKey = String.join("", Files.readAllLines(Paths.get("./public.pem")));
            this.send(this.publicKey);

        } catch (Exception ex) {
            throw new Exception("Couldn't initiate the session");
        }

    }

    /**
     * Generate server public and private keys using RSA.
     */
    public void initKeys() throws Exception {
        // Generate private/public key 

        try {
            System.out.println("Generating server RSA keys");
            Utilities.command("openssl genrsa -out key.pem 2048");
            System.out.println("Keys generated succefully");
            System.out.println("Extracting the public key");
            Utilities.command("openssl rsa -in key.pem -outform PEM -pubout -out public.pem");

        } catch (Exception ex) {
            throw new Exception("Couldn't generte keys");
        }

    }

    public boolean hasKeys() {
        File f = new File("./key.pem");
        return f.exists();
    }

    public static void main(String[] args) {
        // TODO code application logic here
        System.out.println("dasd");
        try {
            Server s = new Server();

            s.open();
            System.out.println("From server:" + s.recieve());

        } catch (Exception ex) {
            System.out.println(ex);
            System.out.print("couldn't connect");
        }
    }

}
