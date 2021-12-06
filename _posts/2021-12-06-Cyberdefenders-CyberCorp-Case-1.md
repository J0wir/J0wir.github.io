## Cyberdefenders - CyberCorp Case 1

This is a write-up of the CyberCorp Case 1 challenge by CyberDefenders. The challenge can be found <a href="https://cyberdefenders.org/labs/74"> here</a>.

### Scenario
CyberCorp company has been informed that its infrastructure is likely to be compromised, as there are a number of anomalies in its outgoing traffic. The anomalies suggest that a known threat group behind this attack.

CyberCorp's Cybersecurity team isolated one of the potentially compromised hosts from the corporate network and collected artifacts necessary for the investigation: memory dump, OS event logs, registry files, Prefetch files, $MFT file, ShimCache, AmCache, network traffic dumps. You will have to analyze the collected artifacts and answer the questions to complete the investigation.

### Tools used for this challenge
-Chainsaw

### Write-up

#### Question 1 - What is the build number (in the format ddddd, where each d is a single decimal number, for example - 12345) of the installed Windows version?

#### Question 2 - What is the parent process PID of the process, that accepts incoming network connections on the port 1900/UDP?

#### Question 3 - What is the IP address of the attacker command and control center, the connection with which was still active at the time of forensic artifacts acquisition?

#### Question 4 - What is the PID of the process where malicious code was located at the moment of forensic artifacts acquisition?










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
