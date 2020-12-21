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
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.*;

/**
 *
 * @author Rami
 */
public class Client {

    Socket socket;
    String publicKey;

    public Client(String host) throws IOException {
        this.socket = new Socket(host, 2000);
    }

    /*
    *    Send message to the server 
     */
    public void send(String message) throws Exception {
        try {
            OutputStream out = this.socket.getOutputStream();
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(out));
            writer.write(message);
            writer.close();
        } catch (Exception ex) {
            throw new Exception("Couldn't send the message");
        }
    }

    /**
     * Recieve a message from the server
     */
    public String recieve() throws Exception {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
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

    public void initSession() throws Exception {
        try {
            this.send("Hello");
            this.publicKey = this.recieve();
            System.out.println("Recieved public key");
            System.out.println(this.publicKey);
        } catch (Exception ex) {
            throw new Exception("Couldn't initiate the session ");
        }

    }

    public static void main(String args[]) {

        try {
            Client client = new Client("127.0.0.1");
            System.out.println("Connected to server");
            System.out.println("Sending message to server");
            client.initSession();

        } catch (Exception ex) {
            System.err.print(ex);
        }
    }
}
