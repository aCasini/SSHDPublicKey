package com.sshd.server;

public class Main {
	
	public static void main(String[] args) {
		System.out.println("Starting .... ");
		SSHDServer server = new SSHDServer();
//		server.start();
//		server.start2();
		server.startServer(2020);
		System.out.println("Completed, the SSHD Server is ready");
	}
}
