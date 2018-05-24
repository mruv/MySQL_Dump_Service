import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Date;
import java.util.Set;
import java.util.HashSet;
import java.util.Base64;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.PreparedStatement;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.IOException;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.RollingFileAppender;



/**
* @author Mwendwa Reuben
* 
*/
public class DatabaseBackUpService {

	// file system
	private final static String BACK_UP_DIR     = "/BACKUPDIR/";
	private final static String LOGS_DIR        = "/var/log/";
	private final static String LOG_FILE_NAME   = "backup_service.log";
	private final static String[] DATABASES     = {"Database1", "Database2"}; // a list of all databases to backup
												

	// logging
	private final static Logger LOG             = Logger.getLogger(DatabaseBackUpService.class);

	// binaries
	private final static String MYSQL_DUMP_BIN  = "/usr/bin/mysqldump";

	// connection
	private final static String USER            = "BACKUPUSER"; // mysql user name
	private static String PWD;

	private final static String STRING          = "BACKUPUSERPASSWORD"; // mysql user password



	
	private static void initializeFileSystem()
	 throws IOException {
		// logs dir
		Path logsPath   = Paths.get(LOGS_DIR);
		Path backUpPath = Paths.get(BACK_UP_DIR);

		if(!Files.exists(logsPath)) {
			// create, if it does not exist
			Files.createDirectories(logsPath);
		}

		if(!Files.exists(backUpPath)) {
			Files.createDirectories(backUpPath);
		}
	}


	private static void initializeLogger() {

		Logger rootLogger = Logger.getRootLogger();
		rootLogger.setLevel(Level.DEBUG);

		try {
			// log to file
			rootLogger.addAppender(
				new RollingFileAppender(
					new PatternLayout(
						"%d{ISO8601} [%-5p] %x - %m%n"),
					LOGS_DIR + LOG_FILE_NAME
					)
				);
		} catch(IOException ex) {
			// do nothing
		}
	}


	
	private static void createSubDirs(String year, String month)
		throws IOException {

		Path yearMonthSubDir  = Paths.get(
			BACK_UP_DIR + year + "/" + month);
		if(!Files.exists(yearMonthSubDir)) {
			Files.createDirectories(yearMonthSubDir);
		}
	}

	private static String exceptionOrigin(Exception exception) {

		return (
			exception.getStackTrace()[0].getClassName() + 
			"." +
			exception.getStackTrace()[0].getMethodName()
			);
	}

	private static SecretKey generateSecretKey()
		throws NoSuchAlgorithmException {

		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		return kgen.generateKey();
	}


	private static IvParameterSpec createIvParameterSpec(byte[] randomData) {

		return new IvParameterSpec(randomData);
	}


	private static Cipher createEncryptionCipher(SecretKey secretKey, IvParameterSpec ivParamSpec)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
		NoSuchPaddingException {

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParamSpec);

		return cipher;
	}

	private static String formatDate(String formatStr, Date rightNow) {
		return new SimpleDateFormat(formatStr).format(rightNow);
	}

	
	private static void backUp(String dumpFileName) {

		String[] args = new String[]{
			MYSQL_DUMP_BIN,
			"-u " + USER, "-p" + PWD,
			"-h 192.168.20.227",
			"--routines","--triggers","--force","--opt",
			"--max_allowed_packet=2G","--single-transaction","--quick",
			"--databases " + String.join(" ", DATABASES)
		};

		// year and month directories
		Date now     = new Date();
		String year  = formatDate("yyyy", now);
		String month = formatDate("MM", now);

		try {
			createSubDirs(year, month);
			// absolute path
			String dumpFileAbsPath = String.join(
				"",
				new String[]{
					BACK_UP_DIR, year,
					"/", month, "/" + dumpFileName
				}
			);

			BufferedReader reader = null;
			BufferedWriter writer = null;
			try {

				final Process proc   = Runtime.getRuntime().exec(String.join(" ", args));

				byte[] iv            = new byte[128/8];
				SecureRandom srandom = SecureRandom.getInstance("SHA1PRNG");
				srandom.nextBytes(iv);


				IvParameterSpec ivspec = createIvParameterSpec(iv);
				SecretKey sKey         = generateSecretKey();
				Cipher cipher          = createEncryptionCipher(sKey, ivspec);

				reader = new BufferedReader(
				    new InputStreamReader(
				    	proc.getInputStream()
				    	)
				    );

				try {
					FileOutputStream fileOstream = new FileOutputStream(dumpFileAbsPath);
					// write encryption/decryption key first
					fileOstream.write(sKey.getEncoded(), 0, 16);
					fileOstream.write(iv, 0, iv.length);

					writer = new BufferedWriter(
					    new OutputStreamWriter(
					    	new GZIPOutputStream(
					    		new CipherOutputStream(
					    			fileOstream, cipher
					    			)
					    		)
					    	)
					    );

					try {
						char[] buff = new char[8192];
						int size;

						while((size = reader.read(buff)) != -1) {
							writer.write(buff, 0, size);
						}

						reader.close();
						writer.close();

					} catch(IOException ex) {
						LOG.error(ex.toString() + " [ in ] " + exceptionOrigin(ex));
					} 

				} catch (IOException ex) {
					LOG.error(ex.toString() + " [ in ] " + exceptionOrigin(ex));
				}

			} catch(InvalidKeyException ex) {
				LOG.error(ex.toString() + " [ in ] " + exceptionOrigin(ex));
			} catch(NoSuchAlgorithmException ex) {
				LOG.error(ex.toString() + " [ in ] " + exceptionOrigin(ex));
			} catch(InvalidAlgorithmParameterException ex) {
				LOG.error(ex.toString() + " [ in ] " + exceptionOrigin(ex));
			} catch(NoSuchPaddingException ex) {
				LOG.error(ex.toString() + " [ in ] " + exceptionOrigin(ex));
			} catch(IOException ex) {
				LOG.error(ex.toString() + " [ in ] " + exceptionOrigin(ex));
			} 
		} catch (IOException ex) {
			LOG.error(ex.toString() + " [ in ] " + exceptionOrigin(ex));
		}
	}

	
	private static void backUpServiceCallBack() {

		Date rightNow         = new Date();

		LOG.info("Back up started at [ " + rightNow.toString() + " ]");

		String dumpFileName   = "BACK_UP_" + formatDate("yyyyMMdd_HHmmss", rightNow) + "_GZ_AES";
		//Set<String> databases = databases();

		LOG.info("Creating back up for [ " + String.join("|", DATABASES) + " ]");

		backUp(dumpFileName);

		LOG.info("Back up [ " + dumpFileName + " ] completed at [ " + new Date().toString() + " ]");
		LOG.info("Done");
		LOG.info(
			"-----------------------------------------------------------" + 
			"-----------------------------------------------------------"
		);

	}

	public static long initialDelay() {
		Calendar now            = Calendar.getInstance();
		GregorianCalendar later = new GregorianCalendar(
			now.get(Calendar.YEAR), now.get(Calendar.MONTH), now.get(Calendar.DATE) + 1, // the following day
			1, 0, 0
			);// 0100hrs


		return Duration.between(
			later.toInstant(), now.toInstant()).abs().toMinutes();
	} 


	public static void startService() {

		ScheduledExecutorService service = 
				Executors.newSingleThreadScheduledExecutor();

		try {

			service.scheduleAtFixedRate(
				new Runnable(){
					@Override
					public void run() {
						// dump
						backUpServiceCallBack();
					}
				}, 1/*initialDelay()*/, 1440, TimeUnit.SECONDS
			);

		} finally {
			// incase of error / successful exit
		}
	}

	public static void main(String[] args) {

		try {

			initPassword();
			initializeFileSystem();
			initializeLogger();

			LOG.info("Back up service started.");
			startService();

		} catch(IOException ex) {
			// could not initialize back up or log directories or could not
			// initialize the logger
			ex.printStackTrace();
		}
	}
}
