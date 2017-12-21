/**
 * Author: Kannan Prasshanth Srinivasan
 * Description: Script for generating secret keys.
 */

import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import javax.crypto.KeyGenerator;

public class RSAKeyGenerator {
    public static final String ALGORITHM = "AES";
    public static final String PRIVATE_KEY_FILE = "secret.key";

    public static void main(String[] args) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(128);
            final Key key = keyGen.generateKey();

            File privateKeyFile = new File(PRIVATE_KEY_FILE);

            if (privateKeyFile.getParentFile() != null) {
                privateKeyFile.getParentFile().mkdirs();
            }
            privateKeyFile.createNewFile();

            ObjectOutputStream privateKeyOS = new ObjectOutputStream(
                    new FileOutputStream(privateKeyFile));
            privateKeyOS.writeObject(key);
            privateKeyOS.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
