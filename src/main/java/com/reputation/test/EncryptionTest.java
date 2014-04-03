package com.reputation.test;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.springframework.util.StringUtils;


public class EncryptionTest {

	private EncryptionTest() {  }
	
	public static void checkProviders() throws Exception {
        final Provider[] providers = Security.getProviders();
        for (int i = 0; i < providers.length; i++) {
            final String name = providers[i].getName();
            final double version = providers[i].getVersion();
            System.out.println("Provider[" + i + "]:: " + name + " " + version);
        }
        System.out.println("Cipher max allowed key length:  " + Cipher.getMaxAllowedKeyLength("AES"));
	}

	/**
     * Random key generation to be used for encryption
     * Prints 3 values
     * 1. global key
     * 2. intermediate key
     * 3. encrypted intermediate key using global key
     * @param algorithm
     * @param size
     * @throws Exception
     * 
     */
    public static void generateAllKeys(String algorithm, int size) throws Exception
    {
        KeyGenerator generator = KeyGenerator.getInstance(algorithm);
        generator.init(size);

        SecretKey globalSharedKey = generator.generateKey();
        SecretKey intermediateKey = generator.generateKey();

        /** prints global key, value to be stored on file system */
        System.out.println("Global key ( on the file system ) : "+"\t"+"\t"+"\t"+"\t"+new String(Base64.encodeBase64(globalSharedKey.getEncoded())));

        /** prints intermediate key */
        System.out.println("Intermediate key (real key for data encryption/decryption) : "+"\t"+new String(Base64.encodeBase64(intermediateKey.getEncoded())));

        byte[] encryptedUserSharedKey = null;

        Cipher c = Cipher.getInstance(algorithm);
        c.init(Cipher.ENCRYPT_MODE, globalSharedKey);
        encryptedUserSharedKey = c.doFinal(intermediateKey.getEncoded());

        String encryptedKey = new String(Base64.encodeBase64(encryptedUserSharedKey));

        /** prints the encrypted intermediate key */
        System.out.println("Encrypted key (using global key, to use in properties file) :"+"\t"+encryptedKey);
    }
    
    

    /**
     * 
     * @param algorithm
     * @param size
     * @param base64EncodedGlobalKey
     * @return base64Encoded key
     * @throws Exception
     */
    public static String generateEncodedKeyUsingExistingGlobal(String algorithm, int size, String base64EncodedGlobalKey) throws Exception
    {
        KeyGenerator generator = KeyGenerator.getInstance(algorithm);
        generator.init(size);

        SecretKey intermediateKey = generator.generateKey();
        
        byte[] existingGlobalEncodedKey = Base64.decodeBase64(base64EncodedGlobalKey);
        SecretKey existingGlobalKey = new SecretKeySpec(existingGlobalEncodedKey, algorithm);


        /** prints global key, value to be stored on file system */
        System.out.println("Existing Global key ( on the file system ) : "+"\t"+"\t"+"\t"+"\t"+base64EncodedGlobalKey);

        /** prints intermediate key */
        System.out.println("Intermediate key (real key for data encryption/decryption) : "+"\t"+new String(Base64.encodeBase64(intermediateKey.getEncoded())));

        byte[] encryptedUserSharedKey = null;

        Cipher c = Cipher.getInstance(algorithm);
        c.init(Cipher.ENCRYPT_MODE, existingGlobalKey);
        encryptedUserSharedKey = c.doFinal(intermediateKey.getEncoded());

        String encryptedKey = new String(Base64.encodeBase64(encryptedUserSharedKey));

        /** prints the encrypted intermediate key */
        System.out.println("Encrypted key (using global key, to use in properties file) :"+"\t"+encryptedKey);
        
        return encryptedKey;
    }
    
    public static SecretKey createKeyFromEncodedKeyString(String algorithm, int size, 
    		String b64EncodedMasterKey, String b64EncodedEncryptedKey) throws Exception {
    	Cipher kc = Cipher.getInstance(algorithm);
        SecretKey masterKey = new SecretKeySpec(Base64.decodeBase64(b64EncodedMasterKey), algorithm);
        kc.init(Cipher.DECRYPT_MODE, masterKey);
        byte[] keyBytes = kc.doFinal(Base64.decodeBase64(b64EncodedEncryptedKey));
    	return new SecretKeySpec( keyBytes, algorithm);
    	
    }
    
    public static void testEncryption_xxx(String algorithm, int size, String b64EncodedMasterKey, String b64EncodedEncryptedKey, String[] messages) throws Exception {
    	System.out.println("### testEncryption BEGIN");
    	
    	// decrypt the key
    	Cipher kc = Cipher.getInstance(algorithm);
        SecretKey masterKey = new SecretKeySpec(Base64.decodeBase64(b64EncodedMasterKey), algorithm);
        kc.init(Cipher.DECRYPT_MODE, masterKey);
        byte[] keyBytes = kc.doFinal(Base64.decodeBase64(b64EncodedEncryptedKey));
    	
    	Cipher c = Cipher.getInstance(algorithm);
    	SecretKey key = new SecretKeySpec( keyBytes, algorithm);
    	c.init(Cipher.ENCRYPT_MODE, key);
    	String[] encryptedMessages = new String[messages.length];
    	long startTime = System.nanoTime();
		for (int i=0; i < messages.length; i++) {
			encryptedMessages[i] = new String( c.doFinal( messages[i].getBytes()));
		}
    	long duration = System.nanoTime() - startTime;
    	System.out.println("### testEncryption END - takes " + duration + " nanoSeconds");
    }
    
    
    public static String[] encryptMessages(String algorithm, SecretKey key, String[] messages) throws Exception {
     	Cipher c = Cipher.getInstance(algorithm);
    	c.init(Cipher.ENCRYPT_MODE, key);
    	String[] encryptedMessages = new String[messages.length];
    	long startTime = System.nanoTime();
		for (int i=0; i < messages.length; i++) {
			encryptedMessages[i] = new String( Base64.encodeBase64( c.doFinal( messages[i].getBytes()) ));
		}
    	long duration = System.nanoTime() - startTime;
    	long durPerLine = duration / encryptedMessages.length;
    	System.out.println("encryptMessages takes " + duration + " nanoSeconds ==> " +
    			durPerLine + " nanoSec per line  ==> " + (duration/1000000000L) + " seconds to process " + 
    			encryptedMessages.length + " messages");
    	return encryptedMessages;
    }
    
    
    public static String[] decryptMessages(String algorithm, SecretKey key, String[] encryptedMessages) throws Exception {
     	Cipher c = Cipher.getInstance(algorithm);
    	c.init(Cipher.DECRYPT_MODE, key);
    	String[] decryptedMessage = new String[encryptedMessages.length];
    	long startTime = System.nanoTime();
		for (int i=0; i < encryptedMessages.length; i++) {
			decryptedMessage[i] = new String( c.doFinal( Base64.decodeBase64(encryptedMessages[i])) );
		}
    	long duration = System.nanoTime() - startTime;
    	long durPerLine = duration / decryptedMessage.length;
    	System.out.println("decryptMessages takes " + duration + " nanoSeconds ==> " +
    			durPerLine + " nanoSec per line  ==> " +
    			(duration/1000000000L) + " seconds to process " + encryptedMessages.length + " messages");
    	return decryptedMessage;
    }
    
    public static void runTest(String algorithm, SecretKey key, String[] messages, String logPrefixStr) throws Exception {
    	String[] encryptedMessages256 = EncryptionTest.encryptMessages(algorithm, key, messages);
    	String[] decryptedMessages256 = EncryptionTest.decryptMessages(algorithm, key, encryptedMessages256);
    	for (int index=0; index < messages.length; index++) {
    		if ( !decryptedMessages256[index].equals(messages[index]) ) {
    			System.out.println(logPrefixStr + " decrypted message["+index+"] does not match.");
    		}
    	}
    }

    public static void main(String[] args) throws Exception {
    	if (args.length < 1) {
    		System.out.println("Please provide file name");
    		System.out.println("USAGE:  java -jar <jar file> datafilename [globalKey filename]");
    		return;
    	}
    	checkProviders();
    	
    	// read from file
    	String filename = args[0];
    	List<String> list = new ArrayList<String>();
    	BufferedReader reader = null;
    	try {
    		reader = new BufferedReader( new FileReader(filename));
    		String line = null;
    		while ( (line = reader.readLine()) != null) {
    			list.add(line);
    		}
    	} catch (Exception e) {
    		System.out.println("Error in reading file");
    		e.printStackTrace();
    		if (reader != null) {
    			try { reader.close(); } catch (Exception ee) {}
    		}
    		return;
    	}
    	reader.close();
    	String[] messages = list.toArray( new String[list.size()] );
    	System.out.println(filename + " has " + messages.length + " lines.");
    
    	String algorithm = "AES";
    	System.out.println("\nTesting AES 128");       
    	KeyGenerator generator128 = KeyGenerator.getInstance(algorithm);
        generator128.init(128);
        SecretKey key128 = generator128.generateKey();   
        runTest(algorithm, key128, messages, "AES 128");

    	System.out.println("\nTesting AES 256");
        KeyGenerator generator256 = KeyGenerator.getInstance(algorithm);
        generator256.init(256);
        SecretKey key256 = generator256.generateKey();  
        runTest(algorithm, key256, messages, "AES 256");

    	if (args.length > 1 && !StringUtils.isEmpty(args[1])) {
    		String globalKeyFilename = args[1];
    		System.out.println("\nTesting with globalKeyFilename " + globalKeyFilename);
    		try {
    			BufferedReader keyReader = new BufferedReader( new FileReader(globalKeyFilename) );
    			String b64GlobalEncodedKey = keyReader.readLine();
    			if (StringUtils.isEmpty(b64GlobalEncodedKey)) {
    				throw new Exception("b64GlobalEncodedKey is null");
    			}
    			String b64EncodedIntermediateKey =  EncryptionTest.generateEncodedKeyUsingExistingGlobal("AES", 256, b64GlobalEncodedKey);
    			System.out.println("GENERATED b64EncodedIntermediateKey from " + globalKeyFilename + ":  " + b64EncodedIntermediateKey);
    			SecretKey thisKey = createKeyFromEncodedKeyString( algorithm, 256, b64GlobalEncodedKey, b64EncodedIntermediateKey);
    			System.out.println();
    			runTest(algorithm, thisKey, messages, "With GlobalKey AES 256");
    			
    		} catch (Exception e) {
    			System.out.println("Cannot process with global key");
    			e.printStackTrace();
    		}
    	}
    }
}
