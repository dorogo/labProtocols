/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package labprotocolshifr;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author user
 */
public class ProtocolDiffieHellman {
    private final User u1;
    private final User u2;
    
    public ProtocolDiffieHellman (User u1, User u2, String fPath) {
        this.u1 = u1;
        this.u2 = u2;
        u1.setPacketPath(fPath);
        u2.setPacketPath(fPath);
    }
    
    public int processProtocol () throws IOException {
        List<Integer> list = new ArrayList();
        // пишем публичные P N в пакет
        list.add(u1.getPKey());
        list.add(u1.getNKey());
        u1.writeData(list);
        //генерим и пишем в пакет открытый ключ юзера1
        list.clear();
        list.add(u1.generatePublicKeyL());
        u1.writeData(list);
        //юзер2 считывает из пакета P N  открытый ключ юзера1
        u2.readData();
        //генерим и пишем в пакет открытый ключ юзера2
        list.clear();
        list.add(u2.generatePublicKeyL());
        u2.writeData(list);
        //юзер1 считывает из пакета открытый ключ юзера 2
        u1.readData();
        //юзер1 генерит финальный ключ и пишет в пакет
        list.clear();
        list.add(u1.generateFinalKey());
        u1.writeData(list);
        //юзер2 генерит финальный ключ и пишет в пакет
        list.clear();
        list.add(u2.generateFinalKey());
        u2.writeData(list);
        //юзеры считывают из файла финальные ключи и сравнивают
        u1.readData();
        u2.readData();
        
        
        u1.showMap();
        u2.showMap();
        
        System.out.print("Final keys are equals: " + u1.checkEqualKeys() + ".\n");
        
        return u1.getFKey();
    }
    
}
