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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Sender {

	private File plainTextMessageFile;
	private byte[] hashArray;
	private byte[] aesArray;
	private String DIGITAL_DIGEST_FILENAME = "message.dd";
	private String AES_CIPHERTEXT_FILE_NAME = "message.add-msg";
	private String RSA_CIPHERTEXTFILE_NAME = "message.rsacihper";

	public Sender() {
		plainTextMessageFile = null;
	}

	private String getEncryptionString() {
		// System.out.println("Sender.getEncryption();");

		String tempString = "";
		File symmetricKeyFile = new File("symmetric.key");
		Scanner fileScanner;

		try {
			fileScanner = new Scanner(symmetricKeyFile);
			tempString = fileScanner.nextLine();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}

		return tempString;
	}

	public void getMessageFileName() {
		// System.out.println("Sender.getMessageFileName()");

		String promptString = "Enter the name of the message file: ";
		String errorString = "Cannot find the specified file.\n";
		Scanner keyboard = new Scanner(System.in);
		File file;
		boolean valid = true;

		do {
			if (!valid)
				System.out.println(errorString);

			System.out.print(promptString);
			file = new File(keyboard.nextLine());

			valid = file.exists() && file.canRead();

		} while (!valid);

		plainTextMessageFile = file;
		System.out.println("File loaded successfully: " + file.getPath());
	}

	/**
	 * Calculates the Digital Digest by for the message using the SHA256 hash function.
	 *
	 * @return true if the hash was saved successfully, false otherwise.
	 */
	public boolean getDigitalDigest() {
		// System.out.println("Sender.getDigitalDigest()");

		final int BUFFER_SIZE = 32 * 1024;
		//System.out.println("... File Size: " + plainTextMessageFile.length());
		//System.out.println("... BUFFER_SIZE: " + BUFFER_SIZE);

		BufferedInputStream encryptBufferIn;
		MessageDigest messageDigest;
		DigestInputStream digitalDigestIn;
		byte[] buffer;
		int bytesRead;

		try {

			// Use buffered input to read small pieces of the message file
			// SHA256(M)
			encryptBufferIn = new BufferedInputStream(new FileInputStream(plainTextMessageFile));
			messageDigest = MessageDigest.getInstance("SHA-256");
			digitalDigestIn = new DigestInputStream(encryptBufferIn, messageDigest);

			buffer = new byte[BUFFER_SIZE];

			// Feed the file into the the the hash function piece by piece
			do {
				bytesRead = digitalDigestIn.read(buffer, 0, BUFFER_SIZE);
			} while (bytesRead == BUFFER_SIZE);

			// Finally get the digital digest
			messageDigest = digitalDigestIn.getMessageDigest();
			digitalDigestIn.close();
			hashArray = messageDigest.digest();

			System.out.println("\nDigital Digest of " + plainTextMessageFile.getName());
			displayHex(hashArray);
			saveByteArray(hashArray, DIGITAL_DIGEST_FILENAME);


		} catch (NoSuchAlgorithmException e) {
			System.out.println("An exception occurred in Sender.getDigitalDigest():\n");
			e.printStackTrace();
			return false;

		} catch (FileNotFoundException e) {
			System.out.println("An FileNotFoundException occurred in Sender.getDigitalDigest():\n");
			System.out.println(plainTextMessageFile + " could was not found.  Please verify the " +
					"file name and try again.\n");
			e.printStackTrace();
			return false;

		} catch (IOException e) {
			System.out.println("An IO exception occurred in Sender.getDigitalDigest():\n");
			e.printStackTrace();
			return false;
		}

		return true;
	}

	/**
	 * Encrypts the SHA256 Hash Code using AES and a symmetric key.  The Hex value of the resulting
	 * cipher text is saves and also displayed on the console
	 * @return
	 */
	public boolean getAesCipherText() {
		// System.out.println("Sender.getAesCipherText()");

		int firstByte = 0;
		int lastByte = 16;

		//File keyFile = new File("Kxy.key");
		Exception exception = null;
		String encryptionKey = getEncryptionString();
		SecureRandom sRandom = new SecureRandom();
		String IV = String.valueOf(sRandom.nextLong()).substring(firstByte, lastByte);


		// Encrypt Digital digest
		// AES-En(Kxy, SHA256(M))
		try {

			if (encryptionKey.equals(""))
				throw new InvalidKeyException("User must provide a 16 character password.");

			Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
			SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
			aesArray = cipher.doFinal(hashArray);

			System.out.println("\nAES Cipher text:");
			displayHex(aesArray);
			saveByteArray(aesArray, AES_CIPHERTEXT_FILE_NAME);

		} catch (NoSuchAlgorithmException e) {
			exception = e;

		} catch (NoSuchProviderException e) {
			exception = e;

		} catch (NoSuchPaddingException e) {
			exception = e;

		} catch (InvalidKeyException e) {
			exception = e;

		} catch (InvalidAlgorithmParameterException e) {
			exception = e;

		} catch (IllegalBlockSizeException e) {
			exception = e;

		} catch (BadPaddingException e) {
			exception = e;

		} catch (UnsupportedEncodingException e) {
			exception = e;

		} finally {
			if (exception != null) {
				System.out.println("An exception occurred in Sender.getAesCipherText():\n");
				System.out.println(exception.toString());
				exception.printStackTrace();
				return false;

			} else {
				return true;
			}
		}
	}

	private PublicKey getKey() {
		ObjectInputStream objectInputStream;
		RSAPublicKeySpec publicKeySpec;
		KeyFactory keyFactory;
		BigInteger mod, exp;


		try {
			objectInputStream =
					new ObjectInputStream(new FileInputStream("YPublic.key"));

			mod = (BigInteger) objectInputStream.readObject();
			exp = (BigInteger) objectInputStream.readObject();

			publicKeySpec = new RSAPublicKeySpec(mod, exp);
			keyFactory = KeyFactory.getInstance("RSA");

			return keyFactory.generatePublic(publicKeySpec);

		} catch (IOException | ClassNotFoundException | InvalidKeySpecException |
				NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return null;
	}


	public void rsaEncryptMessage() {
		System.out.println("Sender.rsaEncryptMessage()");

		final int BUFFER_SIZE = 117;
		PublicKey key = getKey();
		Cipher cipher;
		File file;
		PrintWriter pw;

		try {
			cipher = Cipher.getInstance("RSAECBPKCS1Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, new SecureRandom());

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();

		} catch (NoSuchPaddingException e) {
			e.printStackTrace();

		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}


		byte[] messageByteArray = new byte[BUFFER_SIZE];



		// Save the array
		try {
			file = new File(name);

			pw = new PrintWriter(file);
			for (int i = 0; i < byteArray.length; i++)
				pw.print(byteArray[i]);

			pw.close();

		} catch (FileNotFoundException e) {
			System.err.println("Exception occurred during Sender.saveByteArray() method:");
			e.printStackTrace();


	}

	/**
	 * Prints a byte array in hexadecimal format.
	 *
	 * param byteArray the array to print
	 */
	public void displayHex(byte[] byteArray) {
		// System.out.println("Sender.displayHex()");

		byte[] byteArrayClone = byteArray.clone();

		for (int i = 0, column = 0; i < byteArrayClone.length; i++, column++) {
			System.out.format("%2X ", byteArrayClone[i]);

			if (column >= 15) {
				System.out.println("");
				column = -1;
			}
		}
	}

	/**
	 * Saves array to the specified file
	 *
	 * @param array byte array to save
	 * @param name file name
	 */
	private void saveByteArray(byte[] array, String name) {
		// System.out.println("Sender.saveByteArray()");

		File file;
		PrintWriter pw;
		byte[] byteArray = array.clone();

		// Save the array
		try {
			file = new File(name);

			pw = new PrintWriter(file);
			for (int i = 0; i < byteArray.length; i++)
				pw.print(byteArray[i]);

				pw.close();

		} catch (FileNotFoundException e) {
			System.err.println("Exception occurred during Sender.saveByteArray() method:");
			e.printStackTrace();
		}
	}


	public static void main(String[] args) {
		boolean cont;

		Sender sender = new Sender();
		sender.getMessageFileName();
		cont = sender.getDigitalDigest();

		if (cont)
			cont = sender.getAesCipherText();

		if (cont)
			sender.rsaEncryptMessage();

	}
}
