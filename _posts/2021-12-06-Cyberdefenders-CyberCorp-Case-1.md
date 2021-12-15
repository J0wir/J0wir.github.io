## Cyberdefenders - CyberCorp Case 1

This is a write-up of the CyberCorp Case 1 challenge by CyberDefenders. The challenge can be found <a href="https://cyberdefenders.org/labs/74"> here</a>.

## Scenario
CyberCorp company has been informed that its infrastructure is likely to be compromised, as there are a number of anomalies in its outgoing traffic. The anomalies suggest that a known threat group behind this attack.

CyberCorp's Cybersecurity team isolated one of the potentially compromised hosts from the corporate network and collected artifacts necessary for the investigation: memory dump, OS event logs, registry files, Prefetch files, $MFT file, ShimCache, AmCache, network traffic dumps. You will have to analyze the collected artifacts and answer the questions to complete the investigation.

## Tools used for this challenge
-<a href="https://github.com/countercept/chainsaw"> Chainsaw</a>  
-<a href="https://github.com/volatilityfoundation/volatility"> Volatility</a>  
-<a href="https://ericzimmerman.github.io/#!index.md"> Registry Explorer</a>  
-<a href="https://www.wireshark.org/d"> Wireshark</a>  
-<a href="https://gchq.github.io/CyberChef/"> Cyberchef</a>  
-<a href="https://github.com/decalage2/oletools"> Oletools</a>  

## Write-up

### Question 1 - What is the build number (in the format ddddd, where each d is a single decimal number, for example - 12345) of the installed Windows version?
Every Windows version since 2000, will keep product version information in the Registry. To view this information you can use a tool like Registry Explorer. 

The product version information including the build number is stored in the following key:  
<b>HKLM\Software\Microsoft\Windows NT\CurrentVersion</b>

As shown below this key provides product version information, including the build number.
![image](https://user-images.githubusercontent.com/95626414/144877942-c0a726f5-045f-4a2d-b931-70caf53e79d9.png)

The currentbuild is: <b>17134</b>

### Question 2 - What is the parent process PID of the process, that accepts incoming network connections on the port 1900/UDP?
To answer this question, I’ve used Volatility 2.7 to find incoming network connections and to determine what the parent process is.

Before you can run Volatility commando's, a correct profile for the memory image is needed. To find the profile a plugin called <b>imageinfo</b> was used.

```
vol.py -f memdump.mem imageinfo
```
![Screenshot 2021-12-06 at 16 21 54](https://user-images.githubusercontent.com/95626414/144877393-63dc3104-ee67-41bf-a30f-19c7d943a654.png)

Now that we got the profile, the <b>netscan</b> plugin was used to return all network connections. To filter the output for port 1900 grep was used.

```
vol.py -f memdump.mem --profile=Win10x64_17134 netscan | grep :1900.
```
![Screenshot 2021-12-06 at 16 34 22](https://user-images.githubusercontent.com/95626414/144877508-ddfd1d4a-957c-427d-9af2-3ae9c8bbfa74.png)

All connections on port 1900 are coming from <b>svchost.exe</b> with the PID <b>4688</b>. The parent process can be found by running the <b>pstree</b> module. This module will display the process listing in tree form. To search for the process with PID 4688 a grep filter was used.

```
vol.py -f memdump.mem --profile=Win10x64_17134 pstree | grep 4688
```
The output of this command shows the parent process of svchost.exe is <b>648</b>     
    
### Question 3 - What is the IP address of the attacker command and control center, the connection with which was still active at the time of forensic artifacts acquisition?
While scrolling through the <b>netscan</b> output the following ESTABLISHED connection stood out:
```
TCPv4 192.168.184.130:50133 196.6.112.70:443 ESTABLISHED -1
```
This connection in combination with an entry in the Windows Event Logging shown below, made it clear the answer was: <b>196.6.112.70</b>

![image](https://user-images.githubusercontent.com/95626414/144878901-5f7203e5-dda7-467b-85ab-c3c7916e6253.png)

### Question 4 - What is the PID of the process where malicious code was located at the moment of forensic artifacts acquisition?
To answer this question the <b>pstree</b> output was analysed and some interesting processes were identified. Those processes were spawned by the parent process <b>winlogon.exe</b>.

![image](https://user-images.githubusercontent.com/95626414/145025813-ff2f764b-d463-42a7-8ab1-78425e8b5556.png)  
  
This in combination with malicious code being embedded in the process made me think this was the correct answer.  
![image](https://user-images.githubusercontent.com/95626414/145034909-8e265975-9d44-4119-8fd1-65f16e934734.png)
The PID of <b>winlogon.exe</b> was the correct answer.

### Question 5 - On a compromised system, malicious code, discovered in the previous step, is launched every system start, since the attacker has used one of the persistence techniques. So, what is the name of the autostart entry (those part, that is directly responsible for code execution), used by the attacker for persistence?
This question did take me some time. I was looking at all sort of persistence techniques, but forgot about WMI. While analysing the Windows Event Logs I noticed processes being created (<b>EventID 4688</b>) with the following command line:
```
powershell.exe -noP -ep bypass iex -c \"('C:\\Users\\john.goldberg\\AppData\\Roaming\\Microsoft\\Office\\Recent\\tmpA7Z2.ps1')
```
While looking deeper into this, I noticed a WMI CommandLineEventConsumer with the name: <b>LogRotate Consumer</b> using the same command line.
![image](https://user-images.githubusercontent.com/95626414/145028989-4192ef62-e9ba-408f-9e30-ce4d57bd4936.png)

As shown in the picture above the script is launch every time the user entered his username and password. This technique was used by the Adversary to maintain persistence on the system.

### Question 6 - The autostart entry from the previous step is used to launch the script, which in turn leads to the malicious code execution in the memory of the process, which is discussed in question 4. This code is extracted by script from some system place in the encoded form. The decoded value of this string is executable PE-file. How did Microsoft Antivirus detect this file on 2020-06-21?

This question was easy after completing question 8. The MD5 hash value was calculated and uploaded to <a href="https://www.virustotal.com/gui/file/3890293cd49a688836d53b8a98719690c09b86ced46e677e5b3b8df52a2b4611"> VirtusTotal</a>.

On VirusTotal it shows that Microsoft detects this file as <b>Trojan:Win64/Meterpreter.E</b>.

![image](https://user-images.githubusercontent.com/95626414/145683362-82bc28d0-67b1-4424-928f-e668c35e7ef0.png)

### Question 7 - The process, mentioned in the question 4, isn't the initial process, where malicious code, described in the previous question, was executed by script from autostart. What is the name of the initial process (in the format program.exe), that is spawned by autostart script and used for further malicious code execution, that subsequently migrates to the address space of the process, mentioned in the question 4.

Looking back at the <b>pstree</b> output from question 4, <b>dwm.exe</b> was identified as the answer.

### Question 8 - The autostart entry from the previous step is used to launch the script, which in turn leads to the malicious code execution in the memory of the process, which is discussed in question 4. Provide the URL, which was used to download this script from the Internet during the host compromise. The script that runs at each system star (which is described in question 6) was downloaded to the compromised system from the Internet. Provide the URL, which was used to download this script
While working on question 11, a file named <b>Supplement.dotm</b> was found. To recover this file, a search was performed for <b>.dotm</b> with the <b>filescan</b> module. After the file was identified it was dumped with the <b>dumpfile</b> module.

Now I was left with a <b>dotm.dat</b> file. I decided to run <b>olevbs</b> which is a script to parse OLE and OpenXML files such as MS Office documents
(e.g. Word, Excel), in order to extract VBA Macro code in clear text. Part of the output is shown in the picture below.
![image](https://user-images.githubusercontent.com/95626414/145647862-eb0e6274-fdfb-41dc-91a4-f31a5b8a354a.png)

The output contained the answer to this question: <b>https[:]//raw.githubusercontent[.]com/xia33F/APT/master/payloads/wrapper_page</b>

### Question 9 - The system was compromised as the result of a Microsoft Office document opening, received by email. What is MD5 hash of this document (for example, d41d8cd98f00b204e9800998ecf8427e)?
I started by looking for document files with the <b>filescan</b> module in Volatility. This gave me the below results:
![image](https://user-images.githubusercontent.com/95626414/145031565-cf60a7ec-716b-418b-bdc5-2e1711f089f0.png)  
I guess it's going to be one of the above files. But, how do I receive them in order to calculate the hash value..? This took me a bit to figure out.

In Wireshark an export was created of all ELM files as shown in the picture below. All exported EML files were analysed and one e-mail <b>(Oil Market current state.EML)</b> had a zip file attached to it.

![image](https://user-images.githubusercontent.com/95626414/145417708-4cf42eaa-1658-4215-860d-9d9ff1604002.png)
  
The base64 encoded block for the zip file was copied out of the e-mail headers. The base64 encoded block was decoded and the output saved to a file by using <b>CyberChef</b>. After changing the file extension of the output file to .zip, I was able to extract it's content. This zip file contained a file named <b>Why Saudi Arabia Will Lose The Next Oil Price Was.docx</b>. 

Next, PowerShell was used to calculate the hash value of this file:
```
Get-FileHash -Algorithm md5 'Why Saudi Arabia Will Lose The Next Oil Price Was.docx'
```

This gave the answer to this challenge: <b>aa7ee7f712780aebe9136cabc24bf875</b>

### Question 10 - The document, that was initially opened by user, didn't contain anything malicious itself. It downloaded another document from the Internet as a Microsoft Word template. Malicious code, which has led to the system compromise, is located inside this template directly. What link was used by the first document to download the second document as a template (for example, https://address/file.com)?

After successfully downloading the document in question 9, the next step was to run oletools against the document. This returned us with the answer to this question: <b>http[:]//75.19.45[.]11/Supplement.dotm</b>  
![image](https://user-images.githubusercontent.com/95626414/145423131-7ebb540e-fd15-4d1d-b35e-4ac93d7ed94d.png)

### Question 11 - During the post-exploitation attacker delivered to the compromised host a special Active Directory Enumeration utility. Which link did the attacker use to download this utility (for example, https://address/file.com)?
The answer to this question was found with a little bit of luck. At the start of this challenge I noticed Windows Event Logs in the evidence directory. The first thing I did is run the tool <b>Chainsaw</b> against it. Lately I've been using this tool a lot during IR investigations and would highly recommend it to anyone.
 
![image](https://user-images.githubusercontent.com/95626414/145031916-1a7a0c99-7d35-485d-998f-3d42fe47d9ff.png)
As shown in the picture above the Adverary used <b<http://196.6.112.70/disco.jpg</b> to download the utility.

### Question 12 - As described in the previous question utility has created several files in the compromised system, that subsequently were deleted by an attacker. One of the created files had a bin extension. What is the name of this file (for example, name.bin)?

To answer this question the Master File Table (MFT) was analysed, since this is a database in which information about every file on a NTFS volume is kept. This was done by parsing the MFT file with EricZimmermans his MFT parser. Next, a filter was created on <b>.bin</b> and while scrolling through the results a strange file name was found in the temp directory.
```
.\Windows\Temp	ODNhN2YwNWUtYWFmYy00MDVmLWFhYTQtNGMzM2Q3NmYwMWM4.bin
```

### Question 13 - During the post-exploitation attacker has compromised a privileged user account. What is its password?
As described earlier I've used ChainSaw to analyse the Windows Event Logging. The output of this tool shows the use of <b>net use</b>. The net use command is a Command Prompt command used to connect to, remove, and configure connections to shared resources, like mapped drives and network printers.

In this command the password is shown: <b>!!feb15th2k6!!</b>
![image](https://user-images.githubusercontent.com/95626414/145032229-d2273f20-ee79-4bfc-805b-b396a9d411c3.png)

### Question 14 - What is the name of the tool (for example, program.exe), that probably was used by an attacker to compromise the user account?
The attacker used <b>reg.exe</b> to compromise the user account. The attacker saved the system registry hive to <b>C:\Windows\TEMP\sa.tmp</b>.

### Question 15 - The attacker used a compromised account for unauthorized Domain Controller access. What is the IP address of this Domain Controller?
The answer for this question was found during question 13.

The answer is <b>192.168.184.100</b>
