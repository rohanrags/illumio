package illumio;

import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class Firewall {
	
	//to store the rules in an input file
	private static Map<String,List<String>> rules = new HashMap<>();
	
	//Constructor with filename as parameter. Reads the file contents and stores the input in a map rules for faster accessibility.
	Firewall(String input_file_path) {
		FileInputStream inputStream = null;
		Scanner sc = null;
		try {
			inputStream = new FileInputStream(input_file_path);
		    sc = new Scanner(inputStream, "UTF-8");
		    while (sc.hasNextLine()) {
		        String line = sc.nextLine();
		        String[] splitLine = line.split("\\,");
		        List<String> temp;
		        
		        //storing direction+protocol as key with port+ip_address as value in the rules map.
		        if(rules.containsKey(splitLine[0]+splitLine[1])) {
		        	temp = rules.get(splitLine[0]+splitLine[1]);
		        	temp.add(splitLine[2]+","+splitLine[3]);
		        	rules.put(splitLine[0]+splitLine[1], temp);
		        } else {
		        	temp = new ArrayList<String>();
		        	temp.add(splitLine[2]+","+splitLine[3]);
		        	rules.put(splitLine[0]+splitLine[1], temp);
		        }
		        
		    }
		    
	        inputStream.close();
	        sc.close();
		} catch(Exception e) {
		    e.printStackTrace();
		}
		
	}
	
	private  boolean accept_packet(String direction, String protocol, int port, String ip_address) {
		
		//get the value of specific direction and protocol
		List<String> rule_values = rules.get(direction + protocol);
		boolean port_val=false,ip_val=false;
		
		//iterating through the ports and ip_address allowed for only specified direction and protocol.
		for(String rule_value : rule_values) {
			
			port_val=false;
			ip_val=false;
			
			String[] rule_res = rule_value.split("\\,");
			
			if(rule_res[0].contains("-")) {
				//Range given
				String[] rule_ports = rule_res[0].split("\\-");
				if(port>=Integer.valueOf(rule_ports[0]) && port<=Integer.valueOf(rule_ports[1]))
					port_val=true;
			} else {
				//No Range
				if(Integer.valueOf(rule_res[0])==port)
					port_val=true;
			}
			
			if(rule_res[1].contains("-")) {
				//Range given
				String[] rule_ipAddress = rule_res[1].split("\\-");
				String[] firstIp = rule_ipAddress[0].split("\\.");
				String[] secondIp = rule_ipAddress[1].split("\\.");
				String[] input_Ip = ip_address.split("\\.");
				
				if(Integer.valueOf(input_Ip[0])>=Integer.valueOf(firstIp[0]) && Integer.valueOf(input_Ip[0])<=Integer.valueOf(secondIp[0]))
					if(Integer.valueOf(input_Ip[1])>=Integer.valueOf(firstIp[1]) && Integer.valueOf(input_Ip[1])<=Integer.valueOf(secondIp[1]))
						if(Integer.valueOf(input_Ip[2])>=Integer.valueOf(firstIp[2]) && Integer.valueOf(input_Ip[2])<=Integer.valueOf(secondIp[2]))
							if(Integer.valueOf(input_Ip[3])>=Integer.valueOf(firstIp[3]) && Integer.valueOf(input_Ip[3])<=Integer.valueOf(secondIp[3]))
								ip_val=true;
			} else {
				//No range
				if(ip_address.contentEquals(rule_res[1]))
					ip_val=true;
			}
			
			// both port_val and ip_val should be true for input to be returned as true.
			if(ip_val && port_val)
	 			return true;
		}
		
		//if not returned true means we cannot allow the incoming request.
		return false;
 		
	}
	
	
	public static void main(String[] args) {
		Firewall fw = new Firewall("./src/illumio/output.csv");
		
		System.out.println(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"));
		System.out.println(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"));
		System.out.println(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"));
		System.out.println(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"));
		System.out.println(fw.accept_packet("inbound", "udp", 5, "192.168.2.2"));
		System.out.println(fw.accept_packet("outbound","udp",11359,"110.215.134.125"));
	}
	
	

}
