# <p align="center">ScapyMaison</p>
  

## **Description**

This project is a Python-based network scanning tool that performs four main functions:

Sends ICMP requests to check for live hosts in the network.  
Performs ARP requests to obtain the MAC addresses of live hosts.  
Determines the operating system (Windows/Linux/Unknown) based on the TTL value.  
Scans for open ports within a specified range.  


## 🧑🏻‍💻 Usage
```js
sudo python3 main.py -s [CIDR]
```
To run the program, execute the following command:


sudo python3 main.py -s [CIDR]
The -s argument is required and corresponds to the CIDR of the target network (e.g., 192.168.1.0/24).



## 🧑🏻‍💻 Help
```js
sudo python3 main.py -h
```

Available arguments:

```js
-s [CIDR]: The subnet to scan (required).  
-t [THREADS]: The number of threads for verifying IPs per second (optional).  
-ps [PORT_START]: The starting port for the port scan (optional).  
-pe [PORT_END]: The ending port for the port scan (optional).  
```
        
## 🧑🏻‍💻 Example:
```js
sudo python3 main.py -s 192.168.1.0/24 -t 10 -ps 20 -pe 80
```
        


## **Functionality**  

1. ICMP  Requests: The program sends ICMP requests to check for live hosts in the network. If any machines respond, their IP addresses are stored in the HostUp class.

2. ARP Requests: Once all live IPs are found, the program performs ARP requests to obtain the MAC addresses of the live hosts.

3. Operating System Detection: The program sends an ICMP request and determines the operating system (Windows/Linux/Unknown) based on the TTL value.

4. Port Scanning: Finally, the program scans for open ports within the specified range on each live IP address.

## **Requirements**

Python 3.x  
 ```js
git clone https://github.com/Tw1wX/scapyMaison.git
cd scapyMaison
pip install -r requirements.txt
sudo python3 main.py -h
```

## **Notes**  
Run the script with superuser privileges (sudo) to ensure proper execution and access to network functionalities.

## 🙇 Author
#### TwiwX
- Github: [@TwiwX](https://github.com/Tw1wX)
        
    
    
