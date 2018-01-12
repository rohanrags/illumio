# illumio
Firewalls rules

Firewall constructor is implemented with path as an argument. I have implemented a HashMap with direction and protocol as keys, and the port and ip_address as a value. This is stored in memory in the rules map. So each input data point can call the accept_packet and the accept_packet function can retrieve the values from the map and compare whether to allow or reject the datapoint. This solution takes at the worst case O(n) time with O(n) space complexity due to the map.

Testing : 
1. I have tested my program randomly generated data points and running with my program. It executed quickly without any delays since the map is in memory.
2. Better approach can be done using trees. Each node can a class representing the four parameters. We might end up O(logn) time complexity but at the cost of extra space complexity of the node storage.
3. Each rule is 50 bytes of data. And saying we have 1 million rows, that results in 50 million bytes = ~50 MB data. 50 MB worth of data cannot be kept in memory, so we reduce the amount of data to be read in memory.
4. We can also use software like Lucene or Solr to make the process easier.

Teams : 
1. Platform
2. Data
3. Policy
