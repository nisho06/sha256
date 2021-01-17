/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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

/**
 * This class contains the sample implementation for sha256 hashing algorithm which is used in WSO2 Identity Server.
 */
public class Implementation {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("File name of the password");
        String passwordFile = reader.readLine();
        System.out.println("File name of the salt");
        String saltFile = reader.readLine();
        int count;
        ArrayList<String> mySalts = readSaltValuesFromFile(saltFile + ".txt");
        ArrayList<String> myPasswords = passwordArrayInCharArray(passwordFile + ".txt");

        long start = System.currentTimeMillis();
        for (count = 0; count < 7; count++) {
            String myPassword = sha256Hash(myPasswords.get(count), mySalts.get(count));
            System.out.println(myPassword);
        }
        long end = System.currentTimeMillis();

        double averageElapsedTime = Long.valueOf(end - start).doubleValue() / count;
        System.out.println(averageElapsedTime);
        System.out.println(count);
    }

    /**
     *  This method is responsible for calculating the sha-256 hash value for the respective Password and Salt values.
     * @param password The password which needs to be hashed.
     * @param salt The salt which is unique and needs to be concatanated with passwords before it is hashed.
     * @return The hash String value in Base64 encoding scheme.
     * @throws NoSuchAlgorithmException thrown if there is no Message digest algorithm like "SHA-256".
     * @throws UnsupportedEncodingException thrown if the UTF-8 character encoding is not supported.
     */
    private static String sha256Hash(String password, String salt) throws NoSuchAlgorithmException,
            UnsupportedEncodingException {

        String passwordAndSalt = password + salt;
        char[] charArrayPasswordAndSalt = passwordAndSalt.toCharArray();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] byteValue = digest.digest(new String(charArrayPasswordAndSalt).getBytes("UTF-8"));
        String passwordString = Base64.getEncoder().encodeToString(byteValue);
        return passwordString;
    }

    /**
     * This method is responsible for creating a password array in char[] with the passwords read from the file.
     * @param filename the filename which has the passwords.
     * @return returns the char[] of array which contains all the char [] for respective passwords read from the file.
     * @throws FileNotFoundException This exception is thrown when there is no file in the name given for filename.
     */
    private static ArrayList<String> passwordArrayInCharArray(String filename) throws FileNotFoundException {

        ArrayList<String> passwordArray = new ArrayList<>();
        File myObj = new File(filename);
        Scanner myReader = new Scanner(myObj);
        while (myReader.hasNextLine()) {
            String password = myReader.nextLine();
            passwordArray.add(password);
        }
        myReader.close();
        return passwordArray;
    }

    /**
     * This method is responsible for reading the salt value from a file which contains the salt in each line.
     *
     * @param filename the filename which has the salts.
     * @return String array list which contains all the salt values.
     */
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
            e.printStackTrace(); // TODO: 2021-01-07 end the flow while FileNotFoundException
        }
        return salt;
    }
}

// TODO: 2021-01-13 use default salts
// TODO: 2021-01-13 migrating from sha256 to pbkdf2 , cause which impact.
