# CN-Assignment 1 - 23110160, 23110020


To run the above, first run DNS server file using command python dns_server.py 0.0.0.0 53530 <br>
<br>
Then in different terminal run python dns_client.py 9.pcap 127.0.0.1 53530 report.csv 0 if we don't want to skip .local files else run python dns_client.py 9.pcap 127.0.0.1 53530 report.csv 1 <br>
<br>
The generated report.csv is present in the repository.


