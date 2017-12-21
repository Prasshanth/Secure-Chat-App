/**
 * Author: Kannan Prasshanth Srinivasan
 * Description: Main server service, which authenticates users, generate secret keys and sets up sessions between users.
 */

import javax.crypto.KeyGenerator;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;

public class Server {
    // TO-DO: replace with persistent SQL database
    // HashMap storing user details
    static public volatile HashMap<String, HashMap<String, Object>> userDB;

    // TO-DO: add user registration functionality
    /**
     * Sets up dummy values in DB for testing.
     */
    static void initDB(){
        userDB = new HashMap<String, HashMap<String, Object>>();    // TO-DO: replace with persistent SQL database
        HashMap<String, Object> userRow1 = new HashMap<String, Object>();
        /*  Fields for every user:
            Hostname - the hostname to provide for connections
            Password Hash - the encrypted password
            Checksum Key - the key to use for encrypting or decrypting the checksum
            Message Key - the key to use for encrypting or decrypting messages
            User Online - Whether or not the user is online
            Last Timestamp - Timestamp of last heartbeat received from user
         */
        userRow1.put("hostname", "dc01.utdallas.edu");
        userRow1.put("passwordHash", hash("test"));
        userRow1.put("userOnline", new Boolean(false));
        userRow1.put("lastTimestamp", new Long(0));
        userDB.put("varsha", userRow1);

        HashMap<String, Object> userRow2 = new HashMap<String, Object>();
        userRow2.put("hostname", "dc03.utdallas.edu");
        userRow2.put("passwordHash", hash("test"));
        userRow2.put("userOnline", new Boolean(false));
        userRow2.put("lastTimestamp", new Long(0));
        userDB.put("praveen", userRow2);

        HashMap<String, Object> userRow3 = new HashMap<String, Object>();
        userRow3.put("hostname", "dc04.utdallas.edu");
        userRow3.put("passwordHash", hash("test"));
        userRow3.put("userOnline", new Boolean(false));
        userRow3.put("lastTimestamp", new Long(0));
        userDB.put("raksha", userRow3);

    }

    /**
     * Returns the user database.
     *
     * @return HashMap containing the data store
     */
    static public HashMap<String, HashMap<String, Object>> returnUserDB(){
        return userDB;
    }

    /**
     * Returns whether the user is online.
     *
     * @param username the user to check for
     * @return true if user is online, else false
     */
    static boolean userOnline(String username){
        Boolean userOnlineObject = (Boolean)userDB.get(username).get("userOnline");
        if(userOnlineObject.booleanValue())
            return true;
        else
            return false;
    }

    /**
     * Checks whether a given username exists in the data store.
     *
     * @param username the username to check
     * @return true if username exists, else false
     */
    static boolean userInDB(String username) {
        if(userDB.containsKey(username))
            return true;
        else
            return false;
    }

    /**
     * Sets up the user as online in the data store.
     *
     * @param username the username to be set up as online
     * @param hostname the hostname of the user
     * @param checksumKey the key to use for encrypting or decrypting the checksum for the user
     * @param messageKey the key to user for encrypting or decrypting messages for the user
     * @param timestamp  the timestamp at login
     */
    static void addOnlineUser(String username, String hostname, Key checksumKey, Key messageKey, long timestamp) {
        userDB.get(username).put("hostname", hostname);
        userDB.get(username).put("checksumKey", checksumKey);
        userDB.get(username).put("messageKey", messageKey);
        userDB.get(username).put("lastTimestamp", new Long(timestamp));
        userDB.get(username).put("userOnline", new Boolean(true));
    }

    /**
     * Given username and hash of the password, authenticates a user.
     *
     * @param username the username to be authenticated
     * @param passwordHash the hash of the password to be compared against the data store
     * @return true if password hash and the datastore hash match, else false
     */
    static boolean userAuthenticated(String username, byte[] passwordHash) {
        if(userInDB(username) && Arrays.equals((byte[])userDB.get(username).get("passwordHash"), passwordHash))
            return true;
        else
            return false;
    }

    /**
     * Given a string, returns the MD5 message digest of the string.
     *
     * @param stringToHash the String to hash
     * @return the message digest of the input string
     */
    static byte[] hash(String stringToHash){
        try {
            byte[] passwordBytes = stringToHash.getBytes("UTF-8");
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(passwordBytes);
            return digest;
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Handles the login functionality. Decrypts a login request using the RSA private key, checks user information,
     * and authenticates the user. Returns a HashMap as a result, with the field 'result' being returned as 'success'
     * if the login attempt was successful, otherwise 'failure'.
     *
     * @param message the encrypted message containing the username and password
     * @param outputStream the output stream to write the result to
     */
    static void handleLogin(Object message, ObjectOutputStream outputStream) {
        HashMap<String, Object> inputMessage = (HashMap<String, Object>)CryptoFunctions.RSADecrypt((byte[])message);
        String username = (String)inputMessage.get("username");
        byte[] passwordHash = hash((String)inputMessage.get("password"));
        HashMap<String, String> result = new HashMap<String, String>();
        if(userAuthenticated(username, passwordHash)) {
            String userHostname = (String)inputMessage.get("hostName");
            Key checksumKey = (Key)inputMessage.get("checksumKey");
            Key messageKey = (Key)inputMessage.get("messageKey");
            long timestamp = System.currentTimeMillis();
            addOnlineUser(username, userHostname, checksumKey, messageKey, timestamp);
            result.put("result", "success");
        } else
            result.put("result", "failure");
        try {
            outputStream.writeObject(result);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Generates a secret key.
     *
     * @param keyType AES or DES
     * @return the generated key
     */
    static Key keyGenerator(String keyType) {
        try {
            if (keyType.equals("checksum")) {
                KeyGenerator keyGen = KeyGenerator.getInstance("DES");
                keyGen.init(56);
                return keyGen.generateKey();
            }
            else {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(128);
                return keyGen.generateKey();
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Returns the encryption key for the message or a checksum for a user.
     *
     * @param username the username whose key to return
     * @param keyType 'messageKey' or 'checksumKey'
     * @return the requested key
     */
    static Key getUserKey(String username, String keyType){
        HashMap<String, Object> userRow = userDB.get(username);
        if(keyType.equals("messageKey")) {
            return (Key)userRow.get("messageKey");
        }
        else {
            return (Key)userRow.get("checksumKey");
        }
    }

    /**
     * Returns a ticket for the target user, coming from the current user.
     *
     * @param targetUser the user which the current user wants to establish a session with
     * @param currentUser the user requesting the new session
     * @param sharedCKey the shared checksum key for the new session
     * @param sharedMKey the shared message key for the new session
     * @return an encrypted ticket, encrypted using the target user's keys
     */
    static HashMap<String, byte[]> generateTicket(String targetUser, String currentUser, Key sharedCKey, Key sharedMKey){
        HashMap<String, Object> ticket = new HashMap<String, Object>();
        ticket.put("fromUser", currentUser);
        ticket.put("sharedChecksumKey", sharedCKey);
        ticket.put("sharedMessageKey", sharedMKey);
        Key targetUserMKey = getUserKey(targetUser, "messageKey");
        Key targetUserCKey = getUserKey(targetUser, "checksumKey");
        return CryptoFunctions.encrypt(ticket, targetUserCKey, targetUserMKey);
    }

    /**
     * Updates a user's last heartbeat timestamp.
     *
     * @param user the user whose timestamp to update
     * @param timestamp the timestamp to update with
     */
    static void updateTimestamp(String user, long timestamp) {
        userDB.get(user).put("lastTimestamp", new Long(timestamp));
    }

    /**
     * Returns the hostname for a specified user.
     *
     * @param user the user's whose hostname to return
     * @return the hostname of the specified user
     */
    static String getUserHostname(String user) {
        HashMap<String, Object> userRow = (HashMap<String, Object>)userDB.get(user);
        return (String)userRow.get("hostname");
    }

    /**
     * Sets up a new session with a target user for a current online user. Sends back an encrypted message with
     * the ticket to send to the target user. Sends null if the target user is offline.
     *
     * @param inputMessage The input message containing the user details and the nonce.
     * @param outStream the output stream to which to send the return message.
     */
    static void newSession(Object inputMessage, ObjectOutputStream outStream){
        try{
            HashMap<String, Object> message = (HashMap<String, Object>)inputMessage;
            String targetUser = (String)message.get("targetUser");
            String currentUser = (String)message.get("username");
            String nonce = (String)message.get("nonce");
            String targetUserHostname = getUserHostname(targetUser);
            updateTimestamp(currentUser, System.currentTimeMillis());
            if(!userOnline(targetUser) || !userOnline(currentUser)) {
                outStream.writeObject(null);
            }
            else {
                Key sharedChecksumKey = keyGenerator("checksum");
                Key sharedMessageKey = keyGenerator("message");
                Key currentUserCKey = getUserKey(currentUser, "checksumKey");
                Key currentUserMKey = getUserKey(currentUser, "messageKey");
                HashMap<String, byte[]> ticket = generateTicket(targetUser, currentUser, sharedChecksumKey, sharedMessageKey);
                HashMap<String, Object> returnMessage = new HashMap<String, Object>();
                returnMessage.put("user", targetUser);
                returnMessage.put("nonce", nonce);
                returnMessage.put("checksumKey", sharedChecksumKey);
                returnMessage.put("messageKey", sharedMessageKey);
                returnMessage.put("userHostname", targetUserHostname);
                returnMessage.put("ticket", ticket);
                outStream.writeObject(CryptoFunctions.encrypt(returnMessage, currentUserCKey, currentUserMKey));
            }
        } catch(Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Updates the last heartbeat timestamp for a given user.
     *
     * @param message A Hashmap containing the user details
     * @param username The username belonging to the heartbeat
     */
    static void heartbeat(Object message, String username){
        HashMap<String, byte[]> recastMessage = (HashMap<String, byte[]>)message;
        Key currentUserCKey = getUserKey(username, "checksumKey");
        Key currentUserMKey = getUserKey(username, "messageKey");
        Object decryptedMessage = CryptoFunctions.decrypt(recastMessage, currentUserCKey, currentUserMKey);
        Long timestamp = (Long)decryptedMessage;
        updateTimestamp(username, timestamp.longValue());
    }


    /**
     * Main function for the server process. Initializes the DB, initiates a new heartbeat monitor thread,
     * and listens and responds to messages from clients depending upon the message type.
     *
     * @param args
     */
    public static void main(String[] args) {
        // initialize the database
        initDB();

        // instantiate and start a new heartbeat monitor thread
        HeartbeatMonitor monitor = new HeartbeatMonitor();
        Thread heartbeatMonitorThread = new Thread(monitor);
        heartbeatMonitorThread.start();

        // start listening on port 4444, and respond to client messages depending upon message type.
        try {
            ServerSocket serverSocket = new ServerSocket(4444);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                ObjectOutputStream outputStream = new ObjectOutputStream(clientSocket.getOutputStream());
                ObjectInputStream inputStream = new ObjectInputStream(clientSocket.getInputStream());
                Object input = inputStream.readObject();
                HashMap<String, Object> inputMessage = (HashMap<String, Object>)input;
                if (inputMessage != null) {
                    String messageType = (String) inputMessage.get("messageType");
                    Object message = inputMessage.get("message");

                    if (messageType.equals("login")) {
                        handleLogin(message, outputStream);
                    }
                    if (messageType.equals("newSession")) {
                        newSession(message, outputStream);
                    }
                    if (messageType.equals("heartbeat")) {
                        String username = (String)inputMessage.get("userName");
                        heartbeat(message, username);
                    }
                }
                inputStream.close();
                outputStream.close();
                clientSocket.close();
            }
        }
        catch(Exception e) {
            e.printStackTrace();
        }
    }
}
