/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityp2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 *
 * @author Rami
 */
public class Utilities {

    public enum Protocol {

        InitSession(0),
        Message(1),
        InvalidSession(2),
        ACK(3);
        private final int value;
        private Protocol(int value){
            this.value = value ; 
        }

        public int getValue() {
            return value;
        }
    };

    static String command(String cmd) throws IOException, InterruptedException {

        Runtime run = Runtime.getRuntime();
        Process pr = run.exec(cmd);
        pr.waitFor();
        BufferedReader buf = new BufferedReader(new InputStreamReader(pr.getInputStream()));
        String line = "";
        String output = "";
        while ((line = buf.readLine()) != null) {
            output += line;
        }
        return output;
    }
}
