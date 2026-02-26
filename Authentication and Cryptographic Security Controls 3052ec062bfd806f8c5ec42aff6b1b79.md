# Authentication and Cryptographic Security Controls | A Practical Home Lab Study

![lab_Image.png](Authentication%20and%20Cryptographic%20Security%20Controls/lab_Image.png)

## Project Overview

This home lab project explores the core security mechanisms used to protect modern systems, focusing on authentication and cryptographic security controls within a Linux environment. The lab demonstrates how password policies, encryption, hashing, authentication processes, session management, and process enumeration work together to secure user access and system resources.

Through practical command-line exercises, this project highlights how identities are verified, how sensitive data is protected using cryptographic techniques, and how system processes can be monitored to maintain operational security. The lab provides foundational knowledge essential for cybersecurity students, SOC analysts, and aspiring security professionals.

## Project Objective

The objectives of this project are to:

1. Understand the importance of strong password policies in securing user accounts.
2. Demonstrate encryption techniques (e.g., AES) for protecting data confidentiality.
3. Explain and implement secure hashing (e.g., SHA-256) for password storage and integrity verification.
4. Explore authentication mechanisms and multi-factor verification concepts.
5. Understand session token management and its role in maintaining secure user sessions.
6. Perform Linux process enumeration to monitor active system processes and identify potential security risks.
7. Build practical, hands-on experience with core security controls in a Linux environment.

> NOTE: this project is in 7 parts with different objectives.
> 

## Project Walk Through

### Part 1 - Linux Encryption and Decryption Task

This project is designed to teach you how encryption and decryption work using real Linux terminal commands.
You will encrypt a file, verify it is unreadable, then decrypt it back to its original form.

**This project uses tools that already exist on most Linux systems.**

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image.png)

First step in this part is to, create a new file called **message.txt** using the **echo** command.

```bash
echo "Put in your secret message in quote" > mesage.txt
```

Then you need to verify and view the content of the file created.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%201.png)

Next step is to encrypt the **message.txt file** using the **openssl cryptography toolkit.**

By using the command:

```bash
openssl enc -aes-256-cbc -salt -in message.txt -out encrypt_msg.enc
```

The file was encrypted using AES-256 encryption. A password was set to protect the data. It is very important to set a strong password when dealing with cryptography.

After trying to view the content of the **encrypt_msg.enc file,** we could see rater a scrambled text, marked in red.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%202.png)

Now, the very last steps, we are to decrypt the encrypted file back to plaintext.

> NOTE: before that, it is advisable to delete the previous message.txt file to see the difference.
> 

To decrypt the encrypted message; **encrypt_msg.enc,** I used the command below:

```bash
openssl enc -d -aes-256-cbc -salt -in encrypt_msg.enc -out decrypt_msg.txt
```

After a successful decryption, the plaintext can then be viewed using the “**cat” command.**

**Why encryption alone is not enough for security.**

It only protects data confidentiality during transit or rest, leaving it 
vulnerable while in use, during processing, or if keys are compromised.
Attackers rarely break encryption; they bypass it by stealing 
credentials, exploiting system misconfiguration, or using phishing, including access controls.

**Understanding what I did :**
- message.txt was the original readable data.
- encrypt_msg.enc is the encrypted version of the data.
- Without the correct password, the encrypted file is useless.
- Encryption protected the data, not the system.
- If the password is exposed, encryption fails.

> 
> 
> 
> This project shows how encryption works in real systems.
> It also shows why attackers target passwords and access instead of breaking encryption.
> Understanding this is foundational before learning about passwords, hashes, and authentication.
> 

### Part 2 - Passwords and its Failure

Passwords are meant to prove that you are who you claim to be. In simple terms, a password is a secret that only the real user is supposed to know. If the system receives the correct password, it grants access. The problem with passwords is not the idea itself, but how humans create, reuse, and protect them.
Most password failures happen long before an attacker ever touches a system. People reuse the same password across many websites, slightly modify old passwords, or choose predictable words. When one website is breached, attackers collect leaked passwords and try them on other platforms such as email, social media, and work systems. This is known as credential stuffing, and it works because human behavior is predictable.

**We are to understand how weak passwords handling leads to compromise.**

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%203.png)

First we are to create a new file called **password.txt** where we store the username and the password in the format; **{username}:{password}**

After we need to check and verify if the file has been created in the destination. We can see our password is stored in plaintext, this is insecure.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%204.png)

Next step is to generate a hash for the password to make it impossible to read. By using the command:

```bash
echo -n "password123" | sha256sum
```

we could generate a hash for the **admin** user password using **sha256** encryption algorithm. Finally we copy the hash from the command results and update the password.txt file.

If an attacker steals this file, they cannot see the password directly, but they can attempt to crack the hash offline using common password lists

**Noted points to get.**

- Storing passwords in plain text dangerous because, if the system is compromise, the attacker can read all passwords.
- Hashing better than plain text storage in a sense that it makes the plain text data unreadable to anyone who gets access.
- Hashes can still be cracked when the password is weak the attacker can run hashing tool to see the output plaintext.
- Extra security control that can reduce password risks is by using random password and applying salt.

> This project shows why password handling is one of the weakest points in security and why attackers prefer stealing credentials instead of hacking systems.
> 

Another major weakness is how passwords are stored. Secure systems do not store passwords in plain text. Instead, they store hashes, which are one-way mathematical representations of the password. If weak hashing algorithms are used, or if passwords are not salted, attackers can crack these hashes offline using word-lists and computing power.

Passwords also fail because they are often the only layer of protection. If an attacker obtains the correct password, the system usually cannot tell the difference between the attacker and the real user. This is why passwords alone are no longer sufficient for securing important systems.

### Part 3 - Hashing and Encryption (Deep Dive)

This project is designed to completely clear the confusion between hashing and encryption. Many people use these terms interchangeably, but in real cybersecurity work they mean very different things and are used for very different purposes.
**Hashing** and **Encryption** both transform data, but the intent, design, and security goals
behind them are not the same. Understanding this difference is critical because many real world breaches happen not because systems lacked encryption, but because passwords and authentication data were handled incorrectly.

- **Encryption** protects data that needs to be read again.
- **Hashing** protects data that needs to be verified but never revealed.

Mixing these concepts leads to insecure system design and poor security decisions.
This project is intentionally information-heavy. Understanding matters more than speed.

**To see, in practice, how hashing works and why weak passwords are dangerous.**

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%205.png)

To begin with, we need to to first create a hash of a preferred password of choice, using the command:

```bash
echo -n "<your_password_here>" | sha256sum
```

will create a **sha256 hash** for the password you input, in my case **pass123.**

After we need to copy the hash generated and put it in a file called, **leaked.txt.** Next is to verify if the file has been created.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%206.png)

The second part is to create a different file called **wordlists.txt** where our passwords list will be.

Using the command below will fulfill that task:

```bash
echo -e "password\nadmin123\n123456\npass123\nletmein\ntestuser\ncommon" > wordlists.txt
```

This creates a list of passwords into a text file; **wordlists.txt.** After the step, we need to verify if the wordlists file has been created.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%207.png)

In this last part, we are to compare the hash value to the password lists to verify which one matches the hash, by using the simple script below: 

```bash
while read p; do
  hash=$(echo -n "$p" | sha256sum | awk '{print $1}')
  if [[ "$hash" == 9b8769a4a742959a2d0298c36fb70623f2dfacda8436237df08d8dfd5b37374c ]]; then 
    echo "$p = $hash"
  fi
done < wordlists.txt
```

As usual, using my favorite tool, AI (ChatGPT), to get the script above for my task.

So from the above task accomplished, when you see a matching hash, the password has been cracked.

> **NOTE: AI is a tool for making tasks faster. In Cyber Security, AI will be a valuable tool in your workflow if you understand what it is really doing and understand.**
> 

**Why this works?**

This attack works not because hashing is weak, but because human password choices are weak. Hashing is deterministic, meaning the same input always produces the same output.
Attackers exploit this predictability at massive scale using automation, GPUs, and large
password lists. This is why weak passwords can be cracked in seconds once hashes are leaked

> **Why this project matters:** This project explains one of the most misunderstood topics in cybersecurity.
Understanding hashing versus encryption is foundational knowledge that applies to almost every security role, from blue team to red team.
> 

### Part 4 - Authentication and Session Management (Fundamentals)

This project introduces one of the most important and most exploited areas in cybersecurity:
**authentication** and **session management**.
Many real-world breaches do not happen because passwords are cracked. They happen because applications trust session data too much or handle authentication logic incorrectly.
This project explains authentication and sessions in detail and then walks you through a
simple hands-on exercise to help you understand how sessions work conceptually.

**To observe how sessions work in a real browser environment.**

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%208.png)

First, before logging in, we can see there was no session made because we haven’t interacted with the application by making a request.

To view the session ID from our browser, open your browser **developer tools** and navigate to the **storage** or **cookies** section, by **right clicking** we can achieve this.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%209.png)

This is our LOGIN observation.

Here, after logging in to the application by sending a **POST** request, the server verifies our credentials and generates a **session ID** for us, which we can see marked in red.

What we can observe:

- Session cookies being set
- Cookie names
- Cookie values changing after login

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%2010.png)

This is our LOGOUT observation.

Log out of the website.
What we can observe:

- Session cookie deletion or change
- Session invalidation behavior

After logging out, we could see that the session ID has been changed because;

- the Server deletes the session data or invalidates the session ID and
- the Browser cookie is removed or expired.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%2011.png)

In my note, in order to validate the session ID, I decided to copy the session ID tokens.

> As usual, notes are very important.
> 

From the note, we can see that **only** the **signature** portion of the session changed.

**WHAT SESSIONS REALLY ARE**
A session is a temporary state created by a system to remember that you are logged in.
Instead of asking for your password on every request, the application gives your browser a session identifier, often stored as a cookie.
Every time your browser sends a request, it sends that session identifier. The server checks it and decides whether you are logged in.
If an attacker obtains a valid session identifier, they do not need your password. They can simply reuse the session and impersonate the user.

**Think about what would happen if someone copied your session cookie while you were logged in.**

**DEFENSIVE THINKING**
Secure systems protect sessions by:
- Using secure and HTTPOnly cookies
- Rotating session IDs after login
- Expiring sessions properly
- Binding sessions to context where possible

Authentication is useless if session handling is weak.

> **Why this project matters:** Understanding sessions is critical before learning XSS, CSRF, and account takeover attacks.
This project builds the mental foundation needed for real web exploitation and defense.
> 

### Part 5 - Session Hijacking Fundamentals

This project focuses on session hijacking, one of the most common and most misunderstood causes of real-world account compromise. Many people assume attackers must always steal or crack passwords, but in practice, attackers often bypass passwords entirely by abusing how sessions work.

A session represents trust. Once a system trusts a user, it relies on a session identifier
to maintain that trust. This project explains how that trust can be abused, why it works,
and how defenders attempt to reduce the damage.

**This is a conceptual and observation-based project. You are not exploiting any system. You are learning how attackers think so you can recognize and defend against these issues**.

**Authentication vs Session (Recap)**

Authentication is the process of proving who you are. This usually happens at login when a username and password are verified. Once authentication succeeds, the system does not want to ask for credentials on every request because that would be inefficient and unusable.
Instead, the system creates a session. The session is a temporary representation of your authenticated state. From this point forward, the session identifier, not your password, is what proves you are logged in.
This distinction is critical. Passwords prove identity once. Sessions maintain identity
over time. Attackers understand this difference and design their attacks accordingly.

**What Session Hijacking Means?**

**Session hijacking** occurs when an attacker gains access to a valid session identifier and uses it to impersonate the victim. The system does not know the difference because the session identifier is the only thing it checks to confirm authentication.

This means an attacker does not need to know the password. They do not need to break encryption. They simply need access to the session token while it is still valid.

This is why session hijacking is so dangerous. It bypasses authentication logic entirely and often leaves very little trace for the victim.

**How Sessions Get Expose in Practice.**

Sessions are exposed through many everyday weaknesses. Cross-site scripting allows attackers to steal cookies directly from the browser. Malicious browser extensions can read session data without the user noticing. Insecure Wi-Fi networks can expose sessions if encryption is not enforced.

In some cases, developers accidentally make sessions accessible to JavaScript or fail to expire them properly. In others, malware on the endpoint silently captures session information. None of these attacks require guessing passwords.

**To observe how session cookies behave during authentication and logout.**

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%2012.png)

This time, I am using a vulnerable site named **vulnbank.org.** It is a testing platform to practice web application techniques related to the OWASP Top 10.

- First step is to register as a user, in my case; username = **sessionVictim**
- Next step is to login to the user create and right click to **Inspect** the page.

In this part, we can see there are no session cookies created since we haven’t sent any request to the application.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%2013.png)

After logging in to the user account;

- Using **Browser A** as the victim, we will be presented with a session token made for our user.

Next we are to copy the session cookie from the victim’s browser.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%2014.png)

Next, we open Browser B as our attacker’s browser.

- Visit the same site, **vulnbank.org**
- Open or right click to inspect the DevTools - Application
- Select the Cookie tab
- Replace your session ID with the victim’s (copied) session ID
- After we refresh the page to login as the victim.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%2015.png)

Upon refreshing the page, if session still valid:

- You are now logged in as the victim.

That’s hijacking. No password need, just session token from the browser view.

**Why Strong Passwords are not Enough?**

Strong passwords protect the login step only. Once the user is logged in, the password no longer protects the session. If a session token is stolen, the attacker inherits the  user’s access until the session expires or is invalidated.

This is why logging out matters and why session expiration policies are critical. It is also why systems that keep sessions alive indefinitely are extremely risky.

Understanding this concept changes how you think about account security.

**ATTACKER MINDSET**

From an attacker’s perspective, the session is the real target. Passwords are only useful for gaining the session. Anything that exposes or extends session validity is valuable.

Understanding this mindset helps defenders prioritize the right controls and protections.

**DEFENSIVE THINKING**

Defenders protect sessions by reducing their exposure and lifetime. This includes using secure and HTTPOnly cookies, rotating session identifiers, expiring sessions quickly, and preventing XSS vulnerabilities.

Session security is authentication security. Weak sessions undermine strong passwords.

> **Why This Project Matters:** Session hijacking is at the core of modern web attacks. Understanding it properly is required before learning XSS, CSRF, and account takeover techniques.
> 

### Part 6 - Process and Service Enumeration

This project introduces process and service enumeration, a core skill used by attackers,
defenders, and incident responders. Enumeration is the act of listing and understanding
what exists on a system. Before exploitation, persistence, or defense can happen, the
system must be understood.

This project focuses on Windows because most real-world environments rely heavily on it.

- **A process** is a running instance of a program. It may belong to a user or to the system.
- **A service** is a special type of process designed to run in the background, often with
elevated privileges, and start automatically when the system boots.

Services are especially important because misconfiguration services are a common path to privilege escalation.

**Why Enumeration Comes First?**

Attackers do not act blindly. The first step after gaining access to a system is to
understand what is running, who owns it, and how it behaves. This is called situational
awareness.

Defenders do the same thing during incident response. As a SOC Analyst, enumeration helps answer critical questions such as whether malware is present, whether security tools are running, and whether privileged services are exposed.

**PROCESS ENUMERATION (What to look for.)**

When enumerating processes, you should focus on:
- Process owner (user vs SYSTEM)
- Execution path
- Unexpected names or duplicates
- Processes running from user-writable directories

Malware often hides by using names similar to legitimate system processes.

**SERVICE ENUMERATION (What to look for.)**

Services often run with high privileges. Attackers look for:
- Services running as SYSTEM
- Services with writable binaries
- Services with weak permissions

A single service misconfiguration can allow full system compromise.

**To enumerate processes and services and identify potential security concerns.**

![19.02.2026_15.06.17_REC.png](Authentication%20and%20Cryptographic%20Security%20Controls/19.02.2026_15.06.17_REC.png)

Here, the first command I ran is the **tasklist command.**

- the “**tasklist**” command displays currently and active running processes.

Example output is the results I had above in the image. It is used to:

- **Identify running processes**
- **Get PID (Process ID)**
- **Session Name etc…**

![19.02.2026_15.15.23_REC.png](Authentication%20and%20Cryptographic%20Security%20Controls/19.02.2026_15.15.23_REC.png)

The next command to run is the **tasklist /v.** This command gives a detailed results as compared to the first tasklist command.

It shows:

- **Username running process**
- **CPU time**
- **Window title**
- **Memory Usage of each process and more**

As a SOC Analyst, viewing these processes allows you to spot if malware codes are running or are present on the endpoint.

The “**tasklist /v**” is useful for:

- **Seeing which user launched process**
- **Identifying suspicious execution context**

NOTE: **/V is for verbose, meaning more results or details.**

![19.02.2026_15.24.19_REC.png](Authentication%20and%20Cryptographic%20Security%20Controls/19.02.2026_15.24.19_REC.png)

Our next step is to enumerate services. By running the Windows command, **sc query,** we can see all running services in our results image above.

- **sc = service control**

It is basically used to:

- **Check if service is running**
- **Confirm security tools are active**

![19.02.2026_15.26.34_REC.png](Authentication%20and%20Cryptographic%20Security%20Controls/19.02.2026_15.26.34_REC.png)

Finally, our last check command is “**sc query type= service state= all”**

Breakdown:

- **type= service** = only services and nothing else
- **state= all** = show running plus stopped services

This command shows every service and status either running or stopped.

SOC Analysts use these commands to:

- **Detect disabled security services**
- **Spot newly installed suspicious services**

**What to check for.**

1. Observe which processes run under SYSTEM and which belong to users and
2. Observe service states and names.

**Results Analysis**

**Process: svchost** - it hosts more windows services like a group. It is own by the system administrator. If misconfiguration exits, an attacker can inject a malicious code to run in it.

> **Why this project matter:** Enumeration is the foundation of exploitation and defense. If you cannot understand what is running on a system, you cannot secure it or attack it intelligently.
> 

### Part 7 - Password Policy Failure and Human Behavior

This project explains why strong password policies often fail in real-world environments.
Organizations enforce rules such as password length, complexity, and rotation, yet accounts are still compromised daily.

**The weakness is not the technology.
The weakness is human behavior.**

This project focuses on understanding that gap

**Background**

Many organizations require passwords to:

- Be at least 12 characters long
- Include numbers and symbols
- Be changed regularly
- Avoid reuse

This looks secure in the company’s policy, but users adapt to predictable ways which allows attackers to exploit those adaptations.

**To understand human behavior towards passwords security rule policies.**

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%2016.png)

Upon testing a site and reviewing their password rules; length and complexity, I showed how users approach passwords.

The given password is very predictable one and can be found in most wordlists for cracking passwords. This is very weak and can be cracked in seconds, also does not meet the password requirements as shown below the input field.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%2017.png)

This is another weak password, although it meets the password requirements but can also be cracked in seconds. It is also found in most wordlists files.

Most users just add couple of characters to their old password if told to reset just to meet the policy requirements. This makes attackers observe password reset patterns.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%2018.png)

This password here looks strong with mix of letters, symbol and a number but does not meet the requirements of the site's password standard.

It is very important to follow security policies set in the company or organization, if not followed can cause security problems. Even though the password looks strong, having a minimum password according to the policy can make cracking it easy.

![image.png](Authentication%20and%20Cryptographic%20Security%20Controls/image%2019.png)

This password is strong, meets the standard password requirements and can take a long time to crack. This is not very predictable by attackers, only if they perform a phishing attack.

**Attacker’s mindset**

Attackers do not fight password policies directly.
They study how humans work around them.

Instead of brute force, attackers:

- Observe password patterns
- Exploit reused credentials
- Use phishing to bypass passwords entirely
- Target password reset workflows
- Leverage context and timing

Strong rules do not matter if the human process fails.

Most modern breaches do not start with password cracking.
They start with:

- **Phishing emails**
- **Fake login pages**
- **Reused credentials from another breach**
- **Session hijacking after login**

Passwords are often the least secure part of the system.

> 
> 
> 
> **What This Project Teaches:** 
> 
> Why password policies alone are not security
> How human behavior undermines technical controls
> Why attackers focus on users, not systems
> How to think defensively about authentication
> 

**Final Note**
Security that ignores human behavior will always fail.

**Think like a user.
Think like an attacker.
Think like a defender.**

## Conclusion

This cybersecurity architecture demonstrates a layered defense strategy integrating password policy enforcement, AES encryption, SHA-256 hashing, multi-factor authentication, secure session token management, and Linux process enumeration. 

Each component addresses a distinct aspect of security—protecting credentials, ensuring data confidentiality, verifying identity, maintaining secure sessions, and enabling system-level visibility. Together, these controls reduce the risk of credential compromise, unauthorized access, and post-authentication exploitation. 

The diagram reinforces the principle that effective cybersecurity relies on defense-in-depth, where multiple complementary mechanisms operate cohesively rather than independently.

## Thank You.