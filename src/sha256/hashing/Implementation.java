package sha256.hashing;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;

public class Implementation {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("File name of the password");
        String passwordFile = reader.readLine();
        System.out.println("File name of the salt");
        String saltFile = reader.readLine();
        int count;
        ArrayList<String> mySalts = readSaltValuesFromFile(saltFile+".txt");
        ArrayList<String> myPasswords = passwordArrayInCharArray(passwordFile+".txt");

        long start = System.currentTimeMillis();
        for (  count=0; count<10000 ; count++){
            String myPassword = sha256Hash(myPasswords.get(count), mySalts.get(count));
            System.out.println(myPassword);
        }
        long end = System.currentTimeMillis();

        double averageElapsedTime = Long.valueOf(end - start).doubleValue() / count;
        System.out.println(averageElapsedTime);
        System.out.println(count);
    }

    private static String sha256Hash(String Password, String salt) throws NoSuchAlgorithmException,
            UnsupportedEncodingException {

        String passwordAndSalt = Password+salt;
        char[] charArrayPasswordAndSalt = passwordAndSalt.toCharArray();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] byteValue = digest.digest(new String(charArrayPasswordAndSalt).getBytes("UTF-8"));
        String passwordString = Base64.getEncoder().encodeToString(byteValue);
        return passwordString;
    }


    private static ArrayList<String> passwordArrayInCharArray(String filename) throws FileNotFoundException {

        ArrayList<String> passwordArray = new ArrayList<>();
        File myObj = new File(filename);
        Scanner myReader = new Scanner(myObj);
        int count = 0;
        while (myReader.hasNextLine()) {
            String password = myReader.nextLine();
            passwordArray.add(password);
            count++;
        }
        myReader.close();
        return passwordArray;
    }

    private static ArrayList<String> readSaltValuesFromFile(String filename) {

        ArrayList<String> salt = new ArrayList<>();

        try {
            File myObj = new File(filename);
            Scanner myReader = new Scanner(myObj);
            while (myReader.hasNextLine()) {
                String saltString = myReader.nextLine();
                salt.add(saltString);
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();// TODO: 2021-01-07 end the flow while FileNotFoundException
        }
        return salt;
    }
}

// TODO: 2021-01-13 use default salts
// TODO: 2021-01-13 migrating from sha256 to pbkdf2 , cause which impact.