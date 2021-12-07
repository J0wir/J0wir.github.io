## Cyberdefenders - CyberCorp Case 1

This is a write-up of the CyberCorp Case 1 challenge by CyberDefenders. The challenge can be found <a href="https://cyberdefenders.org/labs/74"> here</a>.

## Scenario
CyberCorp company has been informed that its infrastructure is likely to be compromised, as there are a number of anomalies in its outgoing traffic. The anomalies suggest that a known threat group behind this attack.

CyberCorp's Cybersecurity team isolated one of the potentially compromised hosts from the corporate network and collected artifacts necessary for the investigation: memory dump, OS event logs, registry files, Prefetch files, $MFT file, ShimCache, AmCache, network traffic dumps. You will have to analyze the collected artifacts and answer the questions to complete the investigation.

## Tools used for this challenge
-Chainsaw  
-Volatility 2.7  
-Registry Explorer

## Write-up

### Question 1 - What is the build number (in the format ddddd, where each d is a single decimal number, for example - 12345) of the installed Windows version?
Every Windows version since 2000, will keep product version in the Registry. To view this information you can use a tool like “Registry Explorer”. 

The product version information including the build number is stored in the following key:  
<b>HKLM\Software\Microsoft\Windows NT\CurrentVersion</b>

When viewing this key, we can see the below information, including the build number.
![image](https://user-images.githubusercontent.com/95626414/144877942-c0a726f5-045f-4a2d-b931-70caf53e79d9.png)

As shown in the picture the currentbuild is: <b>17134</b>

### Question 2 - What is the parent process PID of the process, that accepts incoming network connections on the port 1900/UDP?
To answer this question, I’ve used Volatility 2.7 to find incoming network connections and to determine what the parent process is.

Before we can do this, we need to find the correct profile for the memory image. This was done by running the <b>imageinfo</b> plugin.
```
vol.py -f memdump.mem imageinfo
```
![Screenshot 2021-12-06 at 16 21 54](https://user-images.githubusercontent.com/95626414/144877393-63dc3104-ee67-41bf-a30f-19c7d943a654.png)

Next, we use the <b>netscan</b> plugin to return all network connections. Grep was used to filter the output for port 1900.
```
vol.py -f memdump.mem --profile=Win10x64_17134 netscan | grep :1900.
```
![Screenshot 2021-12-06 at 16 34 22](https://user-images.githubusercontent.com/95626414/144877508-ddfd1d4a-957c-427d-9af2-3ae9c8bbfa74.png)

All connections on port 1900 are from <b>svchost.exe</b> with the PID <b>4688</b>. The parent process can be found by running the <b>pstree</b> module. This will display the process listing in tree form. To search for the process with PID 4688 a grep filter was added to the query.

```
vol.py -f memdump.mem --profile=Win10x64_17134 pstree | grep 4688
```
The output of this command shows the parent process of svchost.exe being <b>648</b>     
    
### Question 3 - What is the IP address of the attacker command and control center, the connection with which was still active at the time of forensic artifacts acquisition?
While scrolling through the <b>netscan</b> output I noticed the following ESTABLISHED connection:
```
TCPv4 192.168.184.130:50133 196.6.112.70:443 ESTABLISHED -1
```
This in combination with the below entry in the Windows Event Logging, made me think the anwser is: <b>196.6.112.70</b>

![image](https://user-images.githubusercontent.com/95626414/144878901-5f7203e5-dda7-467b-85ab-c3c7916e6253.png)

### Question 4 - What is the PID of the process where malicious code was located at the moment of forensic artifacts acquisition?
To answer this question I analysed the <b>pstree</b> output and noticed some intressting process being spawned by the parent process <b>winlogon.exe</b>.
![image](https://user-images.githubusercontent.com/95626414/145025813-ff2f764b-d463-42a7-8ab1-78425e8b5556.png)  

This in combination with malicious code being embedded in the process made us think this was the correct answer.
![image](https://user-images.githubusercontent.com/95626414/145034909-8e265975-9d44-4119-8fd1-65f16e934734.png)


The PID of <b>winlogon.exe</b> was the correct answer.

### Question 5 - On a compromised system, malicious code, discovered in the previous step, is launched every system start, since the attacker has used one of the persistence techniques. So, what is the name of the autostart entry (those part, that is directly responsible for code execution), used by the attacker for persistence?
This question did take me some time. I was looking at all sort of persistence techniques, but forgot about WMI. While analysing the Windows Event Logs I noticed some processes being created (<b>EventID 4688</b>) with the below command line:
```
powershell.exe -noP -ep bypass iex -c \"('C:\\Users\\john.goldberg\\AppData\\Roaming\\Microsoft\\Office\\Recent\\tmpA7Z2.ps1')
```
While looking deeper into this, I noticed a WMI CommandLineEventConsumer with the name: <b>LogRotate Consumer</b> using the same command line.
![image](https://user-images.githubusercontent.com/95626414/145028989-4192ef62-e9ba-408f-9e30-ce4d57bd4936.png)

As shown in the picture this script in launched everytime the user enters his username and password.

This was used by the Adversary to maintain persistence on the system.

### Question 6 - The autostart entry from the previous step is used to launch the script, which in turn leads to the malicious code execution in the memory of the process, which is discussed in question 4. This code is extracted by script from some system place in the encoded form. The decoded value of this string is executable PE-file. How did Microsoft Antivirus detect this file on 2020-06-21?

### Question 7 - The process, mentioned in the question 4, isn't the initial process, where malicious code, described in the previous question, was executed by script from autostart. What is the name of the initial process (in the format program.exe), that is spawned by autostart script and used for further malicious code execution, that subsequently migrates to the address space of the process, mentioned in the question 4.

### Question 8 - The autostart entry from the previous step is used to launch the script, which in turn leads to the malicious code execution in the memory of the process, which is discussed in question 4. Provide the URL, which was used to download this script from the Internet during the host compromise. The script that runs at each system star (which is described in question 6) was downloaded to the compromised system from the Internet. Provide the URL, which was used to download this script

### Question 9 - The system was compromised as the result of a Microsoft Office document opening, received by email. What is MD5 hash of this document (for example, d41d8cd98f00b204e9800998ecf8427e)?
I started by looking for document files with the <b>filescan</b> module in Volatility. This gave me the below results:
![image](https://user-images.githubusercontent.com/95626414/145031565-cf60a7ec-716b-418b-bdc5-2e1711f089f0.png)
So I guess it's going to be one of the above files. But, how do I receive them to calculate the hash value..

[TODO}

### Question 10 - The document, that was initially opened by user, didn't contain anything malicious itself. It downloaded another document from the Internet as a Microsoft Word template. Malicious code, which has led to the system compromise, is located inside this template directly. What link was used by the first document to download the second document as a template (for example, https://address/file.com)?

### Question 11 - During the post-exploitation attacker delivered to the compromised host a special Active Directory Enumeration utility. Which link did the attacker use to download this utility (for example, https://address/file.com)?
I found this answer with a little bit of luck. When I saw Windows Event Logs in the evidence directory, the first thing I did is run Chainsaw against it. I been using this tool lately every time I must investigate Event Logging. I would recommend this tool to everyone.
![image](https://user-images.githubusercontent.com/95626414/145031916-1a7a0c99-7d35-485d-998f-3d42fe47d9ff.png)
As shown in the picture the Adverary used </b<http://196.6.112.70/disco.jpg</b> to download the utility.

### Question 12 - As described in the previous question utility has created several files in the compromised system, that subsequently were deleted by an attacker. One of the created files had a bin extension. What is the name of this file (for example, name.bin)?

To awnser this question I looked at the Master File Table (MFT), since this is a database in which information about every file on a NTFS volume is kept. I did this by parsing the MFT file with EricZimmermans his MFT parser. Next, I did filter on <b>.bin</b> and scrolled through the results. While scrolling I noticed a strange file name in the temp directory.
```
.\Windows\Temp	ODNhN2YwNWUtYWFmYy00MDVmLWFhYTQtNGMzM2Q3NmYwMWM4.bin
```

### Question 13 - During the post-exploitation attacker has compromised a privileged user account. What is its password?
As described earlier I've used ChainSaw to analyse the Windows Event Logging. The output of this tool shows the use of <b>net use</b>. In this commando the password is shown: <b>!!feb15th2k6!!</b>
![image](https://user-images.githubusercontent.com/95626414/145032229-d2273f20-ee79-4bfc-805b-b396a9d411c3.png)


### Question 14 - What is the name of the tool (for example, program.exe), that probably was used by an attacker to compromise the user account?

### Question 15 - The attacker used a compromised account for unauthorized Domain Controller access. What is the IP address of this Domain Controller?
The answer for this question was found in the output during question 13.

The answer is <b>192.168.184.100</b>
