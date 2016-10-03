import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.security.Key;

/**
 * Created by Kurt on 2016-10-01.
 */
public class SaveToFile {

	private static File keyFile;
	private static PrintWriter pw;

	public SaveToFile() {
		System.out.println("SaveToFile.SaveToFile()");

	}

	private static void saveToFile(Key key, String keyName) {
		System.out.println("SaveToFile.saveKey()");


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
}
