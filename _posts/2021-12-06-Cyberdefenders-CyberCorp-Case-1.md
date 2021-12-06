## Cyberdefenders - CyberCorp Case 1

This is a write-up of the CyberCorp Case 1 challenge by CyberDefenders. The challenge can be found <a href="https://cyberdefenders.org/labs/74"> here</a>.

### Scenario
CyberCorp company has been informed that its infrastructure is likely to be compromised, as there are a number of anomalies in its outgoing traffic. The anomalies suggest that a known threat group behind this attack.

CyberCorp's Cybersecurity team isolated one of the potentially compromised hosts from the corporate network and collected artifacts necessary for the investigation: memory dump, OS event logs, registry files, Prefetch files, $MFT file, ShimCache, AmCache, network traffic dumps. You will have to analyze the collected artifacts and answer the questions to complete the investigation.

### Tools used for this challenge
-Chainsaw  
-Volatility 2.7

### Write-up

#### Question 1 - What is the build number (in the format ddddd, where each d is a single decimal number, for example - 12345) of the installed Windows version?

#### Question 2 - What is the parent process PID of the process, that accepts incoming network connections on the port 1900/UDP?
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
    
#### Question 3 - What is the IP address of the attacker command and control center, the connection with which was still active at the time of forensic artifacts acquisition?

#### Question 4 - What is the PID of the process where malicious code was located at the moment of forensic artifacts acquisition?

#### Question 5 - On a compromised system, malicious code, discovered in the previous step, is launched every system start, since the attacker has used one of the persistence techniques. So, what is the name of the autostart entry (those part, that is directly responsible for code execution), used by the attacker for persistence?

#### Question 6 - The autostart entry from the previous step is used to launch the script, which in turn leads to the malicious code execution in the memory of the process, which is discussed in question 4. This code is extracted by script from some system place in the encoded form. The decoded value of this string is executable PE-file. How did Microsoft Antivirus detect this file on 2020-06-21?

#### Question 7 - The process, mentioned in the question 4, isn't the initial process, where malicious code, described in the previous question, was executed by script from autostart. What is the name of the initial process (in the format program.exe), that is spawned by autostart script and used for further malicious code execution, that subsequently migrates to the address space of the process, mentioned in the question 4.

#### Question 8 - The autostart entry from the previous step is used to launch the script, which in turn leads to the malicious code execution in the memory of the process, which is discussed in question 4. Provide the URL, which was used to download this script from the Internet during the host compromise. The script that runs at each system star (which is described in question 6) was downloaded to the compromised system from the Internet. Provide the URL, which was used to download this script

#### Question 9 - The system was compromised as the result of a Microsoft Office document opening, received by email. What is MD5 hash of this document (for example, d41d8cd98f00b204e9800998ecf8427e)?

#### Question 10 - The document, that was initially opened by user, didn't contain anything malicious itself. It downloaded another document from the Internet as a Microsoft Word template. Malicious code, which has led to the system compromise, is located inside this template directly. What link was used by the first document to download the second document as a template (for example, https://address/file.com)?

#### Question 11 - During the post-exploitation attacker delivered to the compromised host a special Active Directory Enumeration utility. Which link did the attacker use to download this utility (for example, https://address/file.com)?

#### Question 12 - As described in the previous question utility has created several files in the compromised system, that subsequently were deleted by an attacker. One of the created files had a bin extension. What is the name of this file (for example, name.bin)?

#### Question 13 - During the post-exploitation attacker has compromised a privileged user account. What is its password?

#### Question 14 - What is the name of the tool (for example, program.exe), that probably was used by an attacker to compromise the user account?

#### Question 15 - The attacker used a compromised account for unauthorized Domain Controller access. What is the IP address of this Domain Controller?


Due to a plugin called `jekyll-titles-from-headings` which is supported by GitHub Pages by default. The above header (in the markdown file) will be automatically used as the pages title.

If the file does not start with a header, then the post title will be derived from the filename.

This is a sample blog post. You can talk about all sorts of fun things here.

---

### This is a header

#### Some T-SQL Code

```tsql
SELECT This, [Is], A, Code, Block -- Using SSMS style syntax highlighting
    , REVERSE('abc')
FROM dbo.SomeTable s
    CROSS JOIN dbo.OtherTable o;
```

#### Some PowerShell Code

```powershell
Write-Host "This is a powershell Code block";

# There are many other languages you can use, but the style has to be loaded first

ForEach ($thing in $things) {
    Write-Output "It highlights it using the GitHub style"
}
```
