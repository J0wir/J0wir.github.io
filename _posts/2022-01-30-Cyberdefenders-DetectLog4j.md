## Cyberdefenders - DetectLog4j

This is a write-up of the DetectLog4j challenge by Cyberdefenders. The challenge can be found <a href="https://cyberdefenders.org/blueteam-ctf-challenges/86"> here</a>.

## Scenario
For the last week, log4shell vulnerability has been gaining much attention not for its ability to execute arbitrary commands on the vulnerable system but for the wide range of products that depend on the log4j library. Many of them are not known till now. We created a challenge to test your ability to detect, analyze, mitigate and patch products vulnerable to log4shell.

## Tools used for this challenge
-<a href="https://www.autopsy.com/"> Autopsy</a>  
-<a href="https://www.virustotal.com/gui/home/search"> VirusTotal</a>  
-<a href="https://gchq.github.io/CyberChef/"> Cyberchef</a>  


## Write-up

### Question 1 - What is the computer hostname?
To try something new and mix up the tooling used for maximum learning experience, I decided the give <b>Autopsy</b> a shot.

When loading in the image <b>Autopsy</b> will parse the operating system information. The operating system information shows that the hostname of the computer is <b>vcw65</b>.
![image](https://user-images.githubusercontent.com/95626414/151663702-c8968c52-795c-47ef-8291-288a1197341e.png)

An alternative way of getting the hostname of the computer is using a tool like <b>Registry Explorer</b> and view the following key in de <b>SYSTEM</b> registry hive:
<em>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName</em>

### Question 2 - What is the Timezone of the compromised machine?
Something really cool I learned is that you can view the registry hives with <b>Autopsy</<b>b>. The timezone information is stored in the <b>SYSTEM</b> registry hive, which is located in <b>Windows\System32\config</b>.

Open the hive and go to <b>ControlSet001</b> and click on <b>TimeZoneInformation</b>, this shows the TimeZoneKeyName is <b>Pacific Standard Time</b>. 
![image](https://user-images.githubusercontent.com/95626414/151663843-f77d11f6-68bc-4241-a217-aaafd96af921.png)

Since most forensic reports use the UTC timezone, I assumed we need to convert PST to UTC. As shown in the picture below the difference is 8 hours. So the right answer is <b>UTC-8</b>.
![image](https://user-images.githubusercontent.com/95626414/151663874-7973e92d-735f-44d4-867f-0ee086c7ed4f.png)

### Question 3 - what is the current build number on the system?
<b>Autopsy</b> was used to view the <b>SOFTWARE</b> registry hive, which contains information about the build number. The product version information including the build number is stored in the following key:
<em>HKLM\Software\Microsoft\Windows NT\CurrentVersion</em>

As shown below this key provides product version information, including the build number.
![image](https://user-images.githubusercontent.com/95626414/151663909-f2ff2b77-5d54-48b9-9091-a7bbb687c441.png)

### Question 4 - what is the computer IP?
The answer to this question can also be found in the registry. The IP addresses of the various network interfaces are stored under:
<em>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces</em>
  
As shown in the picture below the IP address is <b>192.168.112.139<b>.
![image](https://user-images.githubusercontent.com/95626414/151663978-2212ba36-12ae-4776-baf5-64e40c2b74e0.png)

### Question 5 - What is the computer IP?
This information can be found in <em>HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters</em> as shown in the picture below:
![image](https://user-images.githubusercontent.com/95626414/151664011-90e50de3-4891-4fbf-9411-6cf1c1c17d13.png)

### Question 6 - When was myoussef user created?
When loading in the image Autopsy will parse OS Accounts information, which show the creation time of the different user accounts. OS accounts information shows that <b>myoussef</b> was created on <b>2021-12-28:07:57:23 CET</b>. However, this was the wrong answer, this timestamp had to be converted to UTC as well. The right answer was: <b>2021-12-28 06:57:23 UTC</b>
![image](https://user-images.githubusercontent.com/95626414/151664061-862c95fe-36be-481e-90c8-e2ccadc66c03.png)

### Question 7 - What is the user mhasan password hint?
The answer to this question can be found in the same view in <b>Autopsy</b> as used for question 6. As shown on the picture below the password hint is: <b>https://www.linkedin.com/in/0xmohamedhasan/</b>
![image](https://user-images.githubusercontent.com/95626414/151664133-f38d79c8-f3e1-4345-a28a-2444e0f586c9.png)

### Question 8 - What is the version of the VMware product installed on the machine?
This question can easily be answered with <b>Autopsy</b>. All the installed programs are parsed and will be shown with one click. After clicking on <b>Installed Programs (89)</b> search through the list until you find the VMware products. As shown on the picture below the version is: <b>6.7.0.40322</b>.
![image](https://user-images.githubusercontent.com/95626414/151664178-5bb6593c-77d6-47d8-b3cc-293e49c88903.png)

### Question 9 - What is the version of the log4j library used by the installed VMware product?
VMware published an <a href="https://kb.vmware.com/s/article/87096"> article</a> on its products being vulnerable to log4j and how to mitigate the risk:

According to the article the vulnerable library should be stored in the following location:
<em>C:\Program Files\VMware\vCenter Server\common-jars\log4j-core-2.11.2.jar</em>

If we navigate to this directory the following files are present:
![image](https://user-images.githubusercontent.com/95626414/151664222-bd2019d3-b318-4dbb-ad01-958a301c54df.png)

As described in the article the vulnerable library </b>log4j-core-2.11.2.jar</b> is being used by VMware. An alternative way of finding the log4j library would be by using one of the many open source scanners. The GitHub repository of <a href="https://github.com/NCSC-NL/log4shell/blob/main/scanning/README.md"> NCSC-NL</a> has a lot of the available scanners.

### Question 10 - What is the log4j library log level specified in the configuration file?
After a bit of searching on Google I found a website describing a file named <b>log4j.properties</b>. The website said the following over this properties file:

<em>The log4j.properties file is a log4j configuration file which keeps properties in key-value pairs. By default, the LogManager looks for a file named log4j.properties in the CLASSPATH.</em>

This sounds like it could contain the answer to this question. An index search in <b>Autopsy</b> was created to locate the file and view its content. As shown in the picture below the category is set to <b>INFO</b>.
![image](https://user-images.githubusercontent.com/95626414/151664292-598732a1-8900-447d-9db1-20ed3cf9c07b.png)

### Question 11 - The attacker exploited log4shell through an HTTP login request. What is the HTTP header used to inject payload?
I was unable to answer this question based on the analyzed evidence. However, on Google I found a <a href="https://www.sprocketsecurity.com/blog/how-to-exploit-log4j-vulnerabilities-in-vmware-vcenter"> blog</a> post describing how to the exploit log4j in the VMware product.
This blog post describes that the vulnerability Is in the <b>X-Forwarded-For</b> header of the vCenter SSO login page. This was also the right answer to this question.

### Question 12 - The attacker used the log4shell.huntress.com payload to detect if vcenter instance is vulnerable. What is the first link of the log4huntress payload?
A search was created in <b>Autopsy</b> to search for the substring <b>huntress.com</b>. The search returned 5 results, but only the <b>websso.log</b> and <b>audit_events.log</b> seem relevant.
![image](https://user-images.githubusercontent.com/95626414/151664446-0a9975fc-dfed-41ae-8831-dc6255f2fa9e.png)

Since the log4j vulnerability is in the SSO login page, I started with investigating the <b>websso.log</b>. This log contained multiple entries with the string <b>log4shell.huntress.com</b>. However, the first payload is: <b>log4shell.huntress.com:1389/b1292f3c-a652-4240-8fb4-59c43141f55a</b>

### Question 13 - When was the first successful login to vsphere WebClient?
I was unable to find login information in the <b>websso.log</b>, so I decided to move on to the <b>audit_events.log</b>. According to Google the vSphere Single-Sign On process writes audit events to the <b>audit_events.log</b> file in the <b>/var/log/audit/sso-events/</b> directory. 

The first event with a successful login is shown below:
<em>[audit_events.log, 2021-12-28T20:39:29.349Z {"user":"administrator@vsphere.local","client":"fe80::7c68:4669:c33c:90a3%5","timestamp":"12/28/2021 12:39:29 PST","description":"User administrator@vsphere.local@fe80::7c68:4669:c33c:90a3%5 logged in with response code 200","eventSeverity":"INFO","type":"com.vmware.sso.LoginSuccess"}</em>

### Question 14 - What is the attacker's IP address?
Searching through the <b>audit_event.log</b> the IP address <b>192.168.112.128</b> was identified, which was the correct answer to this question.
<em>2021-12-29T01:58:58.790Z {"user":"mlabib@VCW65","client":"192.168.112.128","timestamp":"12/28/2021 17:58:58 PST","description":"User mlabib@VCW65@192.168.112.128 logged in with response code 200","eventSeverity":"INFO","type":"com.vmware.sso.LoginSuccess"}</em>

### Question 15 - What is the port the attacker used to receive the cobalt strike reverse shell?
Often Cobalt strike is deployed with a Base64 encoded PowerShell command. Before parsing all the Windows event logs, I started by simply opening <b>Microsoft-Windows-PowerShell%4Operational.evtx</b> to identify possible deployment with PowerShell.

In the second entry of this Windows Event Log, a remotely executed command was identified.
![image](https://user-images.githubusercontent.com/95626414/151664692-f5d7c96a-87d8-4a36-8a47-7c871c696aa3.png)

In this event a block of Base64 encoded code was found, which was decoded with <b>Cyberchef</b>. The decoded text gave some clues like the malicious IP addresses found earlier and an user-agent string.

<b>Mandiant</b> their <b>speakeasy</b> tool was used to emulate this command. Unfortunately, <b>speakeasy</b> was not installed in my home setup. However, it was installed in the forensic lab at the office I work.
https://github.com/mandiant/speakeasy

The reverse shell was received on <b>192.168.112:128:1337</b>
  
### Question 16 - What is the script name published by VMware to mitigate log4shell vulnerability?
VMware published an <a href="https://kb.vmware.com/s/article/87081"> article</a> on mitigating the log4shell vulnerabilities.

Below is a snipped of this article:
<em>IMPORTANT: vc_log4j_mitigator.py will now mitigate CVE-2021-44228 and CVE-2021-45046 on vCenter Server end-to-end without extra steps. This script replaces the need to run remove_log4j_class.py and vmsa-2021-0028-kb87081.py independently. However, it is not necessary to run if you've already used those in your environment.</em>

The answer to this question: <b>vc_log4j_mitigator.py</b>

### Question 17 - In some cases, you may not be able to update the products used in your network. What is the system property needed to set to 'true' to work around the log4shell vulnerability?
Apache published an <a href="https://logging.apache.org/log4j/2.x/security.html"> article</a> about the log4j security vulnerabilities. In this article the following mitigation measure is mentioned:
<em>setting system property log4j2.formatMsgNoLookups or environment variable LOG4J_FORMAT_MSG_NO_LOOKUPS to true for releases</em>

The answer to this question is: <b>log4j2.formatMsgNoLookups</b>

### Question 18 - What is the script name published by VMware to mitigate log4shell vulnerability?
The Apache article about the log4j security vulnerabilities, described <b>log4j</b> version <b>2.15.0</b> was the version fixing the <b>CVE-2021-44228</b> vulnerability.
  
### Question 19 - Removing JNDIlookup.class may help in mitigating log4shell. What is the sha256 hash of the JNDILookup.class?
The earlier identified file <b>log4j-core-2.11.2.jar</b> was extracted out of <b>Autopsy</b>. This file can be found in the following location: <b>\VMWare\vCenter Server\VMWare Identity Services\log4j-core-2.11.2.jar</b>

The cool thing about <b>jar</b> files is the fact you can extract the content like you can with a ZIP file. In the extracted content <b>JNDILookup.class</b> was identified. The SHA256 hash value was calculated by PowerShell with the command shown in the picture below.
![image](https://user-images.githubusercontent.com/95626414/151664989-8bc2522b-02c1-4519-a90a-897f2d828d89.png)

The answer to this question is: <b>0F038A1E0AA0AFF76D66D1440C88A2B35A3D023AD8B2E3BAC8E25A3208499F7E</b>
  
### Question 20 - What is the script name published by VMware to mitigate log4shell vulnerability?
After analysing the <b>JNDILookup.class</b> the value <b>java:comp/env/</b> was identified.

### Question 21 - What is the executable used by the attacker to gain persistence?
If you think about persistence one of the first things you think about are the Run keys. This information is stored in the <b>NTUSER.DAT</b>. This file contains the settings and preferences for each user. The <b>NTUSER.DAT</b> file of the user <b>Administrator.WIN-B633EO9K91M</b> contained an interesting entry as shown in the picture below.
![image](https://user-images.githubusercontent.com/95626414/151665058-bc1d93eb-c635-4d5c-943a-99ad9cfc5593.png)

The <b>NTUSER.DAT</b> can be found by going to <em>SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</em>

The answer to this question is: <b>baaaackdooor.exe</b>

### Question 22 - When was the first submission of ransomware to virustotal?
During question 21 a file named <b>baaaackdoor.exe</b> was identified. The SHA256 hash value of this file was: <b>f2e3f685256e5f31b05fc9f9ca470f527d7fdae28fa3190c8eba179473e20789</b>

After submitting the SHA256 hash value to <b>VirusTotal</b>, the history of the sample can be seen. The history contains information as the creation time of the sample, the first time seen and the last submission. 

The first time this sample was seen was on <b>2021-12-11 22:57:01</b> as shown in the picture below.
![image](https://user-images.githubusercontent.com/95626414/151665113-a4cd8a65-14fa-4458-b61c-6ba8b41d25d0.png)

### Question 23 - The ransomware downloads a text file from an external server. What is the key used to decrypt the URL?
Since I have no experience with reverse engineering a malware binary, I started by using Google to see if I could find the answer that way. In <b>VirusTotal</b> you can view the detection names given to the malware by the different antivirus solutions.
![image](https://user-images.githubusercontent.com/95626414/151665169-761f4fdd-70bd-4805-ac45-b92fc612d02e.png)

Most antivirus solutions detect the malware as <b>Khonsari</b>. With this knowledge I went to Google and found a great threat <a href="https://www.bluvector.io/threat-report/khonsari-new-malware-apache-log4j/
"> report</a> analyzing the malware sample.

A snipped from the threat report:
<em>The most significant attempt at anti-analysis by the authors, is merely to utilize a basic string obfuscation technique. In more technical terms, strings within the sample are obfuscated by XOR’ing each string with a unique key, consisting of an eight character, alphabetic string. A simple Python script was written during analysis in order to reverse the obfuscation. The decrypted strings are shown below.</em>

The threat report also shows some eight character alphabetic strings, which I tried as answer and luckily one of them worked! The answer to this question is: <b>GoaahQrC</b>

### Question 24 - What is the ISP that owns that IP that serves the text file?
Again <b>VirusTotal</b> was used to answer this question, since it shows all contacted domains by the binary.
![image](https://user-images.githubusercontent.com/95626414/151665270-51a58b5f-4520-44a1-8a33-88345dcf0a76.png)

As shown in the picture an <b>Amazon</b> domain was contacted.
  
### Question 25 - The ransomware check for extensions to exclude them from the encryption process. What is the second extension the ransomware checks for?
In the same threat report used to answer question 23, another extension is mentioned. The answer to this question is: <b>ini</b>.
  
