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
 * This program creates RSA Key pairs (public and private) and saves them to the current directory.
 * Also, the program prompts the user for a 16-character password.
 *
 * Use the main method to create multiple keys or change the names of the keys.
 *
 * Limitations:
 *
 * 1. Run time exceptions are caught, print a message to the console and then the program
 *      terminates.
 * 2. Running this program will automatically overwrite any previously saved keys.  Keys should be
 *      moved to a different directory to prevent lose of key.
 * 3. The keys and passwords created by this program are not secure; this program is for
 *      demonstration and educational purposes only.
 *
 */

package KeyGen;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

public class KeyGen {
	private static final String PUBLIC_KEY_FILE_NAME = "Public.key";
	private static final String PRIVATE_KEY_FILE_NAME = "Private.key";
	private static final String SYMMETRIC_KEY_FILE_NAME = "symmetric.key";


	/**
	 * Create a new instance of KeyGen
	 */
	public KeyGen() {
		//System.out.println("New KeyGen instance: " + this.toString());
	}

	/**
	 * Creates and saves a new RSA key pair to the current directory.
	 *
	 * @param keyName  Name of the file to save the key in.
	 */
	public static void makeKeyPair(String keyName) {
		//System.out.println("KeyGen.makeKeys()");

		SecureRandom sRandom = new SecureRandom();
		KeyPairGenerator kpGenerator;
		KeyPair keyPair;
		Key publicKey, privateKey;

		String pubFileName = keyName.concat(PUBLIC_KEY_FILE_NAME);
		String priFileName = keyName.concat(PRIVATE_KEY_FILE_NAME);

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
			System.out.println("Exception in KeyGen.makeKeys.\n"
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
		//System.out.println("KeyGen.saveKeys()");

		File keyFile;
		PrintWriter pw;

		// Save public and private keys
		try {
			keyFile = new File(keyName);

			pw = new PrintWriter(keyFile);
			System.out.println(key.get);
			pw.print(key.getEncoded());

			pw.close();

		} catch (FileNotFoundException e) {
			System.err.println("Exception occurred during KenGen.saveKeys() method:");
			e.printStackTrace();
		}
	}

	/**
	 * Save the user's choosen string
	 *
	 * @param s string to save
	 * @param fileName the name of the file
	 */
	private static void saveString(String s, String fileName) {
		//System.out.println("KeyGen.saveString()");

		File stringFile;
		PrintWriter pw;
		String filePath;

		// Save public and private keys
		try {
			stringFile = new File(fileName);
			filePath = stringFile.getPath().concat("\\" + fileName);

			pw = new PrintWriter(stringFile);
			pw.print(s);
			pw.close();

			System.out.println("Input saved: " + filePath);

		} catch (FileNotFoundException e) {
			System.out.println("Exception occurred during KenGen.saveKeys() method:");
			e.printStackTrace();
		}
	}


	/**
	 * Make a symmetric key from the user's chosen password.
	 *
	 * */
	public void getSymmetricKey() {
		// System.out.println("KeyGen.getSymmetricKey()");

		// Output message prompts to the user
		String messageString = "Please enter your 16 character password: ";
		String errorString = "The password must have exactly 16 characters.";

		// Input from the user
		String tempString;
		Scanner keyboardScanner = new Scanner(System.in);

		boolean isValid;

		// Get 16-character password for the symmetric key
		do {
			System.out.print(messageString);
			tempString = keyboardScanner.nextLine();

			// Validate input length
			if (tempString.length() != 16) {
				isValid = false;
				System.out.println("\n" + errorString);

			} else
				isValid = true;

		} while (!isValid);

		// Convert plain text to Secret Key

		saveString(tempString,SYMMETRIC_KEY_FILE_NAME);

	}
	public static void main(String[] args) {
		// System.out.println("KenGen.main()");

		KeyGen kg = new KeyGen();
		kg.makeKeyPair("X");
		kg.makeKeyPair("Y");

		System.out.println("RSA Key pairs have been created for X and Y");

		kg.getSymmetricKey();
		System.out.println("Symmetric key saved for X and Y");

		System.exit(0);
	}
}