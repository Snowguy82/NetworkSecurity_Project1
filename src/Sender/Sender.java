/**
 * Sender
 *
 * Program by Kurt Pennington
 * October 3, 2016
 *
 *
 * Project I:  Public-Key encrypted and authentic digital digest
 * Computer Science 3750:  Computer and Network Security
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
package Sender;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Sender {

	private Object message;

	public Sender() {


	}

	public boolean getFile() {
		System.out.println("Sender.getFile()");

		String promptString = "Please the name of the file to encrypt: ";
		String errorString = "Cannot find the specified file.";
		String encryptFileString;
		Scanner keyboard = new Scanner(System.in);

		BufferedInputStream encryptFile;
		MessageDigest messageDigest;
		DigestInputStream digitalDigestIn;



		System.out.print(promptString);
		encryptFileString = keyboard.nextLine();


		try {

			encryptFile = new BufferedInputStream(new FileInputStream(encryptFileString));
			messageDigest = MessageDigest.getInstance("SHA-256");
			digitalDigestIn = new DigestInputStream(encryptFile, messageDigest);

		} catch (FileNotFoundException | NoSuchAlgorithmException e) {
			System.out.println("An exception occurred in SEnder.getFile(): " + e.toString());
			e.printStackTrace();
		} finally {

		}


	}

	public static void main(String[] args) {
		Sender sender = new Sender();
		sender.getFile();

	}
}
