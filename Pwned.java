/*
 * @author  Adam Sorrenti
 * Date:    2019-03-13
 */
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import javax.swing.JOptionPane;
public class Pwned {

    private static String toSHA1(String psw) throws NoSuchAlgorithmException {
        MessageDigest mDigest;
        byte[] result;
        StringBuffer sb;

        mDigest = MessageDigest.getInstance("SHA1");
        result = mDigest.digest(psw.getBytes());
        sb = new StringBuffer();
        for (byte b : result)
        {
            sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }
    private static ArrayList<String[]> getURL(String head) throws IOException
    {
        ArrayList<String[]> hashes = new ArrayList<>();
        URL url = new URL("https://api.pwnedpasswords.com/range/"+head);
        URLConnection urlc = url.openConnection();
                urlc.setRequestProperty("User-Agent", "Mozilla 5.0 (Windows; U; "+ "Windows NT 5.1; en-US; rv:1.8.0.11) ");
        // read text returned by server
        BufferedReader in = new BufferedReader(new InputStreamReader(urlc.getInputStream()));

        String line;
        while ((line = in.readLine()) != null) {
            hashes.add(line.split(":"));
        }
        in.close();
        return hashes;
    }
    private static int isPwned(String sha1) throws IOException {
        String head = sha1.substring(0,5);
        String tail = sha1.substring(sha1.length() - 6, sha1.length() - 1);
        ArrayList<String[]> hashes = getURL(head);

        for (String[] hash : hashes)
        {
            String t = hash[0].substring(hash[0].length() - 6, hash[0].length() - 1);
            if (tail.equalsIgnoreCase(t))
                return Integer.parseInt(hash[1]);
        }

        return 0;
    }
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {

        while(true) {
            JOptionPane pane = new JOptionPane();
            String passwd = pane.showInputDialog(null, "Input your password:", "", JOptionPane.OK_CANCEL_OPTION);
            if (passwd == null)
                return;
            else if (passwd.isEmpty())
                continue;
            String passwdHash = toSHA1(passwd);

            int occurrences = isPwned(passwdHash);
            if (occurrences == 0) {
                int i = JOptionPane.showConfirmDialog(null, passwd + " has not been PWNED!", "", JOptionPane.OK_CANCEL_OPTION);
                if (i == JOptionPane.CANCEL_OPTION)
                    return;
            } else {
                int i = JOptionPane.showConfirmDialog(null, passwd + " has been PWNED!\nOccurrences: " + occurrences, "", JOptionPane.OK_CANCEL_OPTION);
                if (i == JOptionPane.CANCEL_OPTION)
                    return;
            }
        }
    }
}
