/**
 * KeyGen
 *
 * Program by Kurt Pennington
 * October 3, 2016
 *
 * Computer Science 3750:  Computer and Network Security
 * Project I
 * Metropolitan State University of Denver
 *
 * This program creates RSA Key pairs (public and private) and saves then to the current directory.
 * Also, the program prompts the user for a 16-character password to be used as a symmetric key.
 *
 * Use the main method to create multiple keys or change the names of the keys.
 *
 * Limitations:
 *
 * 1. Run time exceptions are caught, print a message to the console and then the program
 *      terminates.
 * 2. Running this program will automatically overwrite any previously saved keys.  Keys should be
 *      moved to a different directory to prevent lose of key.
 */

package KeyGen;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.spec.SecretKeySpec;

public class KeyGen {
	private static final String PUBLIC_FILE_NAME = "Public.key";
	private static final String PRIVATE_FILE_NAME = "Private.key";


	/**
	 * Create a new instance of KeyGen
	 */
	public KeyGen() {
		System.out.println("New KeyGen instance: " + this.toString());
	}

	/**
	 * Creates and saves a new RSA key pair to the current directory.
	 *
	 * @param keyName  Name of the file to save the key in.
	 */
	public static void makeKeyPair(String keyName) {
		System.out.println("KeyGen.makeKeys()");

		SecureRandom sRandom = new SecureRandom();
		KeyPairGenerator kpGenerator;
		KeyPair keyPair;
		Key publicKey, privateKey;

		String pubFileName = keyName.concat(PUBLIC_FILE_NAME);
		String priFileName = keyName.concat(PRIVATE_FILE_NAME);

		// Create new keys
		try {
			kpGenerator= KeyPairGenerator.getInstance("RSA");
			kpGenerator.initialize(1024, sRandom);
			keyPair = kpGenerator.generateKeyPair();

			publicKey = keyPair.getPublic();
			privateKey = keyPair.getPrivate();

			saveKey(publicKey, pubFileName);
			saveKey(privateKey, priFileName);


		} catch (NoSuchAlgorithmException | InvalidParameterException e) {
			System.err.println("Exception in KeyGen.makeKeys.\n"
					+ e.getLocalizedMessage());

		}
	} // End makeKeyPair(String name)

	/**
	 * Save a security key to the current directory
	 *
	 * @param key the key to be saved
	 * @param keyName the name of the file to save the key in.
	 */
	private static void saveKey(Key key, String keyName) {
		System.out.println("KeyGen.saveKeys()");

		File keyFile;
		PrintWriter pw;

		//System.out.println("KeyGen.saveKeys().fileNames: " + pubFileName + " " + priFileName);

		// Save public and private keys
		try {
			keyFile = new File(keyName);

			pw = new PrintWriter(keyFile);
			pw.println(key);
			pw.close();

		} catch (FileNotFoundException e) {
			System.err.println("Exception occurred during KenGen.saveKeys() method:");
			e.printStackTrace();
		}
	}


	/**
	 * Make a symmetric key from the user's chosen password.
	 *
	 * @param keyName  file name for saving the key
	 * */
	public void getSymmetricKey(String keyName) {
		System.out.println("KeyGen.getSymmetricKey()");

		// User messages
		String messageString = "Please enter your 16 character password: ";
		String errorString = "The password must have exactly 16 characters.";

		// User input
		String tempString;
		String keyFileName = keyName;
		Scanner keyboardScanner = new Scanner(System.in);

		SecretKeySpec key;
		boolean isValid = true;

		// Get 16-character symmetric key
		do {
			System.out.print(messageString);
			tempString = keyboardScanner.nextLine();

			// Validate input length
			if (tempString.length() != 15) {
				isValid = false;
				System.out.println("\n" + errorString);

			} else
				isValid = true;

		} while (!isValid);

		// Convert plain text to Secret Key
		try {
			key = new SecretKeySpec(tempString.getBytes("UTF-8"), "AES");
			saveKey(key,keyFileName);

		} catch (UnsupportedEncodingException e) {
			System.err.println("Exception occurred during KenGen.saveKeys() method:");
			e.printStackTrace();
		}
	}
	public static void main(String[] args) {
		System.out.println("KenGen.main()");

		KeyGen kg = new KeyGen();
		kg.makeKeyPair("X");
		kg.makeKeyPair("Y");

		System.out.println("RSA Key pairs have been created for X and Y");

		kg.getSymmetricKey("Kxy.key");
		System.out.println("Symmetric key created for X and Y");

		System.exit(0);
	}
}