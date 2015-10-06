package com.sshd.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.Base64;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.sftp.SftpSubsystem;

public class SSHDServer {
	private static final String knownKey = "{SSH2.PUBLIC.KEY}";
	
	public void start2(){
		SshServer sshd = SshServer.setUpDefaultServer();
	        sshd.setPort(8001);
		        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider("hostkey.ser"));
		        sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
//		        sshd.setShellFactory(new EchoShellFactory());
		        sshd.setCommandFactory(new ScpCommandFactory());
		        sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
		    		
		    		@Override
		    		public boolean authenticate(String arg0, String arg1, ServerSession arg2) {
		    			System.out.println("Authentication is in progress ... ");
		    			return true;
		    		}
		        });
		    	try {
					sshd.start();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
	}

	/** 
	 * Starts a ssh server on the provided port.
	 * @param port the port to listen to.
	 * @return the server.
	 * @throws IOException if so.
	 */
	public SshServer startServer(int port){
		SshServer sshd = SshServer.setUpDefaultServer();
		sshd.setPort(port);
		sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider("hostkey.ser"));
		sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
			
			@Override
			public boolean authenticate(String s, PublicKey publicKey, ServerSession serverSession) {
				return true;
			}
		});
		sshd.setCommandFactory(new ScpCommandFactory());
		try {
			sshd.start();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return sshd;
	}

	public void start() {
	   SshServer sshd = SshServer.setUpDefaultServer();
	   sshd.setHost("localhost");
	   sshd.setPort(2223);
			
	   sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider("hostkey.ser"));
       sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
       sshd.setCommandFactory(new ScpCommandFactory());
	   
//	   sshd.setPasswordAuthenticator(new PasswordAuthenticator() {
//		
//		@Override
//		public boolean authenticate(String arg0, String arg1, ServerSession arg2) {
//			System.out.println("Authentication is in progress ... ");
//			return true;
//		}
//	});
	
       sshd.setPublickeyAuthenticator(new PublickeyAuthenticator() {
    	      public boolean authenticate(String username, PublicKey key, ServerSession session) {
    	         if(key instanceof RSAPublicKey) {
    	            String s1 = new String(encode((RSAPublicKey) key));
    	            String s2 = new String(Base64.decodeBase64(knownKey.getBytes()));					
    	            return s1.equals(s2); //Returns true if the key matches our known key, this allows auth to proceed.
    	         }
    	         return false; //Doesn't handle other key types currently.
    	      }
    	   });
	   
	   try {
		sshd.start();
	} catch (IOException e) {
		e.printStackTrace();
	}
	}
	
	//Converts a Java RSA PK to SSH2 Format.
	public static byte[] encode(RSAPublicKey key) {
	   try {
	      ByteArrayOutputStream buf = new ByteArrayOutputStream();
	      byte[] name = "ssh-rsa".getBytes("US-ASCII");
	      write(name, buf);
	      write(key.getPublicExponent().toByteArray(), buf);
	      write(key.getModulus().toByteArray(), buf);
	      return buf.toByteArray();
	   }
	   catch(Exception e) {
	      e.printStackTrace();
	   }
	   return null;
	}

	private static void write(byte[] str, OutputStream os) throws IOException {
	   for (int shift = 24; shift >= 0; shift -= 8)
	      os.write((str.length >>> shift) & 0xFF);
	   os.write(str);
	}
}
