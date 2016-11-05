/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package labprotocolshifr;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author dorogo
 */
public final class User {
    private static final String P_KEY_STRING = "P_KEY";
    private static final String N_KEY_STRING = "N_KEY";
    private static final String PB_KEY_STRING = "PUBLIC_KEY";
    private static final String F_KEY_STRING = "FINAL_KEY";
    
    private static int id_static = 0;
    
    private int xKey;   //private key
    private final int currId;
    private String packetPath;
    private final Map<String, Integer> mapKeys;
    
    
    public User () {
        currId = ++id_static;
        mapKeys = new LinkedHashMap<>();
        resetKeys();
        
    }
    
    public void resetKeys() {
        xKey = (int) (Math.random() * 50) + 15;
        mapKeys.clear();
        mapKeys.put(P_KEY_STRING, 0);
        mapKeys.put(N_KEY_STRING, 0);
        mapKeys.put(PB_KEY_STRING+"1", 0);
        mapKeys.put(PB_KEY_STRING+"2", 0);
        mapKeys.put(F_KEY_STRING+"1", 0);
        mapKeys.put(F_KEY_STRING+"2", 0);
    }
    
    public void setPacketPath (String s) {
        packetPath = s;
    }
    
    public void setPKey (int p) {
        mapKeys.put(P_KEY_STRING, p);
    }
    
    public int getPKey () {
        return mapKeys.get(P_KEY_STRING);
    }
    
    public void setNKey (int n) {
        mapKeys.put(N_KEY_STRING, n);
    }
    
    public int getNKey () {
        return mapKeys.get(N_KEY_STRING);
    }
    
    public void setSecretKey (int x) {
        xKey = x;
    }
    
    public int getSecretKey () {
        return xKey;
    }
    
    public int generatePublicKeyL () {
        BigInteger d,e;
        int i;
        d = BigInteger.valueOf((long)mapKeys.get(P_KEY_STRING));
        e = d.pow(xKey);
        d = e.mod(BigInteger.valueOf((long)mapKeys.get(N_KEY_STRING)));
        i = d.intValue();
        mapKeys.put(PB_KEY_STRING + Integer.toString(currId), i);
        return i;
    }
    
    
    public boolean readData() throws FileNotFoundException, IOException {
        BufferedReader bReader = FileHelper.getBufferedReader(packetPath);
        String line;
        for (String s : mapKeys.keySet()) {
            if ((line = bReader.readLine()) != null) {
                mapKeys.put(s, Integer.parseInt(line));
            }
        }
        return true;
    }
    
    public int generateFinalKey () {
        int tmpId = (currId == 1) ? 2 : 1;
        BigInteger d,e;
        int i;
        d = BigInteger.valueOf((long)mapKeys.get(PB_KEY_STRING + Integer.toString(tmpId)));
        e = d.pow(xKey);
        d = e.mod(BigInteger.valueOf((long)mapKeys.get(N_KEY_STRING)));
        i = d.intValue();
        mapKeys.put(F_KEY_STRING + Integer.toString(currId), i);
        return i;
    }
    
    public void showMap() {
        System.out.println("\nUser #"+currId + " keys.");
        System.out.println("xKey = "+xKey);
        for (String s : mapKeys.keySet()) {
            System.out.println(""+s+" = "+ mapKeys.get(s));
        }
        
    }
    
    public boolean writeData(List<Integer> list) {
        String tmp = "";
        for (Integer x : list) {
            tmp += Long.toString(x) + "\n";
        }
        return FileHelper.writeString(tmp, packetPath, true);
    }

    public boolean checkEqualKeys() {
        return mapKeys.get(F_KEY_STRING + "1").equals(mapKeys.get(F_KEY_STRING + "2"));
    }
    
    public int getFKey () {
        return mapKeys.get(F_KEY_STRING + "1");
    }
    
    public String getPacketPath () {
        return packetPath;
    }
    
    public String encryptRSA (String srcText) {
        System.out.println("Source text:"+srcText);
        String encryptedText = "";
        int l = srcText.length();
        BigInteger c,m;
        for (int i = 0; i < l; i++) {
            m = BigInteger.valueOf((long)srcText.charAt(i));
            c = m.modPow(BigInteger.valueOf((long)this.getPKey()), BigInteger.valueOf((long)this.getNKey()));
            encryptedText += "," + c.toString();
        }
        System.out.println("Encrypted text by user #" + currId + ": " + encryptedText);
        return encryptedText;
    }
    
    public String decryptRSA (String srcText) {
        String decryptedText = "";
        String tmp = "";
        int l = srcText.length();
        BigInteger c,m;
        for (int i = 1; i < l; i++) {
            if (Character.toString(srcText.charAt(i-1)).matches("[,]")) {
                tmp = "";
                do {                    
                    tmp += srcText.charAt(i);
                    i++;
                } while (i < l && srcText.charAt(i) != ',');
                c = BigInteger.valueOf((long)Integer.parseInt(tmp));
                m = c.modPow(BigInteger.valueOf((long)this.getSecretKey()), BigInteger.valueOf((long)this.getNKey()));
                decryptedText += (char) m.intValue();
            }
        }
        System.out.println("Decrypted text by user #" + currId + ": " + decryptedText);
        return "\n" + decryptedText;
    }
}
