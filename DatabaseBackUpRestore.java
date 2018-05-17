import java.util.Base64;
import java.util.zip.GZIPInputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.IOException;
import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.CommandLine;


public class DatabaseBackUpRestore {

	// inner
	private static class BackUpDecryptionKey {

		private final byte[] sKey;
		private final byte[] randomIv;

		public BackUpDecryptionKey(byte[] sKey, byte[] randomIv){
			this.sKey     = sKey;
			this.randomIv = randomIv;
		}

		public byte[] getSecretKeyBytes() {
			return this.sKey;
		}

		public byte[] getRandomIvBytes() {
			return this.randomIv;
		}
	}

	private static Cipher initializeDecryptionCipher(BackUpDecryptionKey dKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
		NoSuchPaddingException {

		SecretKey sKey         = new SecretKeySpec(dKey.getSecretKeyBytes(), "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(dKey.getRandomIvBytes());

		Cipher cipher          = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, sKey, ivSpec);

		System.out.println("Cipher initialized");
		return cipher;
	}


	private static void restore(String backUpPath) {


		BufferedWriter writer       = null;
		BufferedReader reader       = null;
		FileInputStream fileIstream = null;

		try {
			File backUpFile     = new File(backUpPath);
			fileIstream         = new FileInputStream(backUpFile);

			byte[] encodedKey   = new byte[16];
			byte[] ivByteString = new byte[16];

			fileIstream.read(encodedKey);
			fileIstream.read(ivByteString);

			//System.out.println(encodedKey + "   " + ivByteString); 
			BackUpDecryptionKey backUpDecKey = new BackUpDecryptionKey(encodedKey, ivByteString);
			try {

				Cipher cipher          = initializeDecryptionCipher(backUpDecKey);
				String restoreFileName = backUpFile.getName() + ".sql";

				try {
					// new SQL dump
					writer =
						new BufferedWriter(
							new OutputStreamWriter(
								new FileOutputStream(// write SQL dump to a new file
									restoreFileName
									)
								)
							);

					// encrypted archive
					reader =
						new BufferedReader(
							new InputStreamReader(// byte stream --> char stream
								new GZIPInputStream(// decompress
									new CipherInputStream(// decrypt before decompressing
										fileIstream, cipher
										)
									)
								)
							);

					char[] buff         = new char[8192];
					//long sizeRead        = 0L;
					int len;

					System.out.println("Decrypting ...");
					while((len = reader.read(buff)) != -1) {
						//sizeRead += (long) len;
						writer.write(buff, 0, len);

					}

					System.out.println();
					System.out.println("Back up (sql) : " + restoreFileName);
					System.out.println("Done");

				} catch(IOException ex) {
					System.out.println(ex);
				} finally {
					try { reader.close(); writer.close(); } catch(IOException ex) {} 
				}

			} catch(InvalidKeyException ex) {
				System.out.println(ex);
			} catch(InvalidAlgorithmParameterException ex) {
				System.out.println(ex);
			} catch(NoSuchPaddingException ex) {
				System.out.println(ex);
			} catch(NoSuchAlgorithmException ex) {
				System.out.println(ex);
			}

		} 
		/*catch(SQLException ex) {
			System.out.println(ex);
		} catch(ClassNotFoundException ex) {
			System.out.println(ex);
		} 
		*/
		catch(IOException ex) {
			System.out.println(ex);
		} finally {
			try { 
				fileIstream.close();
				
				if (writer != null)
					writer.close();

				if(reader != null)
					reader.close();
			} catch(IOException ex) {}
		}
	}


	private static String parseCommandLineArgs(String[] args) {

		Options options = new Options();

		Option fileOpt  = new Option("f", "file", true, "path to the back up file to be restored");
		fileOpt.setRequired(true);

		options.addOption(fileOpt);

		CommandLineParser cliParser = new DefaultParser();
		HelpFormatter hFormatter    = new HelpFormatter();
		CommandLine cmdLine;

		try {
			cmdLine = cliParser.parse(options, args);

			return cmdLine.getOptionValue("file");

		} catch(ParseException ex) {
			System.out.println(ex.getMessage());
			hFormatter.printHelp("utility-name", options);

			//System.exit(0);
			return null;
		}
	}


	public static void main(String[] args) {

		String path = parseCommandLineArgs(args);
		
		if (path != null)
			restore(path);
	}
}