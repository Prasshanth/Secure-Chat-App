/**
 * Author: Kannan Prasshanth Srinivasan
 * Description: Service for checking whether users are online based on received heartbeat messages.
 */

import java.util.HashMap;

public class HeartbeatMonitor implements Runnable {
    /**
     * Thread which keeps running until the program is terminated. For every user in the database, it checks for the
     * time of the last heartbeat message received from the user. If the last heartbeat for a particular user was
     * received more than 90 seconds ago, then it sets the user as offline, the user would need to authenticate once
     * again in order to chat with other users.
     */
    public void run(){
        while(true) {
            long currentTimestamp = System.currentTimeMillis();
            for(String username : Server.userDB.keySet()){
                HashMap<String, Object> userRow = Server.userDB.get(username);
                Long lastTimestamp = (Long)userRow.get("lastTimestamp");
                Boolean userOn = (Boolean)userRow.get("userOnline");
                if(currentTimestamp - lastTimestamp.longValue() > 90000 && userOn.booleanValue() == true){
                    System.out.println("User " + username + "has not sent heartbeat for 90 seconds, setting user as offline");
                    userRow.put("userOnline", new Boolean(false));
                }
            }
        }
    }
}
