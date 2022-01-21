## Cyberdefenders - Phishy

This is a write-up of the Phishy challenge by Cyberdefenders. The challenge can be found <a href="https://cyberdefenders.org/labs/60"> here</a>.

## Scenario
A company’s employee joined a fake iPhone giveaway. Our team took a disk image of the employee's system for further analysis. As a security analyst, you are tasked to identify how the system was compromised.

## Tools used for this challenge
-<a href="https://www.exterro.com/ftk-imager#:~:text=FTK%C2%AE%20Imager%20is%20a,(FTK%C2%AE)%20is%20warranted."> FTK imager</a>  
-<a href="https://accessdata.com/product-download/registry-viewer-2-0-0"> AccessData Registry Viewer</a>  
-<a href="https://github.com/andreas-mausch/whatsapp-viewer"> WhatsApp viewer</a>  
-<a href="https://www.virustotal.com/gui/home/search"> VirusTotal</a>  
-<a href="https://gchq.github.io/CyberChef/"> Cyberchef</a>  
-<a href="https://github.com/decalage2/oletools"> Oletools</a>  
-<a href="https://www.sqlite.org/index.html"> SQlite</a>  
-<a href="https://www.nirsoft.net/utils/passwordfox.html"> Passwordfox</a>  

## Write-up

### Question 1 - What is the hostname of the victim machine?
We started by mounting <b>GiveAway.ad1</b> with FTK imager. After successfully mounting the image, the <b>SYSTEM</b> registry hive was exported out of the image. The hostname is stored in the <b>SYSTEM</b> hive, more specific located in the following location:
<em><b>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName</b></em>

![image](https://user-images.githubusercontent.com/95626414/150549319-d5664601-faf4-4c47-9877-99786e753b0e.png)

As shown in the image the hostname of the machine is: <b>WIN-NF3JQEU4G0T</b>

### Question 2 - What is the messaging app installed on the victim machine?
<b>WhatsApp.exe</b> was identified while clicking through the filesystem. This file was located in the Downloads directory of the user <b>Semah</b>.

The answer is: <b>WhatsApp</b>

### Question 3 - The attacker tricked the victim into downloading a malicious document. Provide the full download URL.
During question 2 <b>WhatsApp.exe</b> was identified. So, I guess this question has something to do with WhatsApp. The database containing the WhatsApp messages was exported out of FTK imager. 

The database can be found in the following location:
<em><b>Users\Semah\AppData\Roaming\WhatsApp\Databases\msgstore.db</b></em>

The database was loaded into <b>WhatsApp viewer</b>. As shown in the picture below, the user received a message about <b>5 iPhone winners</b>. The user was tricked into downloading <b>http[:]//appIe.com/IPhone-Winners.doc</b>, which is highly likely a malicious document.
 
 ![image](https://user-images.githubusercontent.com/95626414/150550355-ee5f438f-e2a6-4f79-af95-98b768031428.png)

### Question 4 - Multiple streams contain macros in the document. Provide the number of the highest stream.
The document <b>iPhone-Winners.doc</b> can be found in the download folder of <b>Semah</b>. To identify the largest macro stream <b>oledump</b> was used.

Answer: <b>10</b>

### Question 5 - The macro executed a program. Provide the program name?
<b>Oletools</b> was used to find malicious macros in this document. As shown in the picture below, the file contains a suspicious macro(s).

![image](https://user-images.githubusercontent.com/95626414/150550588-a5fbd295-824e-48c1-8820-c7a3095e5798.png)

Since we know the file contains a malicious macro, we now want to extract and analyze this code with <b>Olevba</b>. Unfortunately, as shown in the picture below the code is obfuscated. 

![image](https://user-images.githubusercontent.com/95626414/150550650-787abd91-3876-45d9-8b8e-d962cc200343.png)

Fortunately, you can provide the parameter <b>–deobf</b> to deobfuscate this code. The output shows that PowerShell was likely executed as result of the macro.

![image](https://user-images.githubusercontent.com/95626414/150550718-30afac71-1ab5-4347-a7cc-32791b9e2020.png)

Answer: <b>PowerShell</b>
  
### Question 6 - The macro downloaded a malicious file. Provide the full download URL.
During question 5 we deobfuscated the VBA macro. In the output a VBA string likely Base64 encoded was found.

![image](https://user-images.githubusercontent.com/95626414/150550935-8b2dcf49-0879-438d-878c-880f42147348.png)

A tool I often use named <b>CyberChef</b> was used to decode this string.

![image](https://user-images.githubusercontent.com/95626414/150550990-0fa1ad1c-ca40-47d3-bfe0-0b638409eab7.png)

The decoded string is a PowerShell command.<b>Invoke-webrequest</b> was performed to download <b>http[:]//appIe.com/Iphone.exe</b> and save the file to <b>C:\Temp\Iphone.exe</b>.

Answer: <b>http[:]//appIe.com/Iphone.exe</b>

### Question 7 - Where was the malicious file downloaded to? (Provide the full path)
As described in question 6, the file was saved to <b>C:\Temp\Iphone.exe</b>.


### Question 8 - What is the name of the framework used to create the malware?

The MD5 hash for <b>Iphone.exe</b> was calculated: <b>7C827274C062374E992EB8F33D0C188C</b>

A search was performed on Google for this hash value. The only result was a Hybrid Analysis report. However, this didn’t tell us what framework was used to create the malware.

Next, the hash value was submitted to <b>VirusTotal</b> showing the below results.

![image](https://user-images.githubusercontent.com/95626414/150551502-7760dbc9-4f9a-4fe7-8af9-02aea027873a.png)

Some antiviruses do recognize the malware as Meterpreter, which is a Metasploit framework for payloads and shells. In addition, there is a comment placed by THOR, which is a great tool I often use during my work. A YARA signature detected the sample as a Metasploit payload.

![image](https://user-images.githubusercontent.com/95626414/150551594-6c013e89-dc6a-4f90-bffd-e525179f66c4.png)

I decided to try <b>Metasploit</b> as an answer, and it was the correct one!

### Question 9 - What is the attacker's IP address?
<b>VirusTotal</b> is a great tool and shows the contacted IP-addresses by the uploaded sample. As shown in the picture two IP-addresses were identified.

![image](https://user-images.githubusercontent.com/95626414/150551769-3869dc34-9e8a-414f-826e-ee9bf58f93d7.png)

With <b>192.168.0.30</b> being a local IP-addresses, the right answer must be <b>155.94.69.27</b>.

### Question 10 - The fake giveaway used a login page to collect user information. Provide the full URL of the login page?
Based on the browser software installed on the system, I assumed it had something to do with Firefox. The relevant file most likely containing the answer to the question is <b>places.sqlite</b>.

This file can be found in the following location:
<em><b>Users\Semah\AppData\Roaming\Mozilla\Firefox\profiles\pyb51x2n.default-release\places.sqlite</em></b>

<b>Places.sqlite</b> was loaded into <b>SQlite</b>. In the output the familiar <b>appIe.com</b> domain was found. When taking a closer look, a fake giveaway URL was identified:
 <b>http[:]//appIe.competitions.com/login.php</b>


### Question 11 - What is the password the user submitted to the login page?
During question 10 the <b>login.php</b> page was identified. Let’s see if we can find some saved credentials. The Mozilla profile for <b>Semah</b> was exported with FTK imager and loaded into <b>passwordfox</b>. The tool found only one entry, but it was the right one!

![image](https://user-images.githubusercontent.com/95626414/150552255-0206a562-ab44-476c-908e-d2017d651157.png)

The answer: <b>GacsriicUZMY4xiAF4yl</b>



