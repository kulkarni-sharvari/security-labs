## Goal: 
Show technical depth, chaining of steps, and security research thinking. 400–600 words.

## Lab details
Lab: [Lab name]

Level: Practitioner

Vulnerability Class: SQL Injection — [subtype: UNION-based / Blind / Error-based / Out-of-band]

Lab URL: [PortSwigger lab link]

Date Completed: [Date]

Time to Solve: [Honest estimate — good for your own tracking]

## Vulnerability Summary
[2–3 sentences. What is the vulnerability, where does it live, and what's the impact if exploited in a real app?]

## Reconnaissance
[What did you probe first? What responses told you something was injectable? What was your process before crafting the exploit?]
Indicators observed:

[e.g., "Single quote ' caused a 500 error — indicates unsanitized input reaching SQL parser"]
[e.g., "Time delay confirmed blind injection point"]
[e.g., "Column count determined via ORDER BY incrementing"]


## Exploitation — Step by Step
### Step 1: [Name the step]
[What you did and why]
sql[payload]
[What response you got and what it told you]

### Step 2: [Name the step]
[What you did and why]
sql[payload]
[What response you got and what it told you]

### Step 3: [Continue as needed]

### Key Payload(s)
sql-- Final working payload
[payload here]

-- What the full injected query looks like
[reconstructed query]

### Tools Used

 Manual (Burp Suite Repeater)
 Burp Suite Intruder
 sqlmap
 Other: ___


Note: For portfolio purposes, always attempt manual exploitation first. sqlmap is a tool to verify — not a substitute for understanding.


## The Fix
[Specific, code-level remediation. Match the fix to the stack if you can.]
java// Spring Boot — parameterized query
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement ps = connection.prepareStatement(sql);
ps.setString(1, username);
ps.setString(2, password);
Additional mitigations:

[e.g., Least privilege DB user — app user should not have DROP or ALTER rights]
[e.g., WAF rule to flag SQL metacharacters in input]
[e.g., Error handling — never expose raw SQL errors to the client]


## What I Found Interesting / Unexpected
[This is your researcher voice. What surprised you? What would you do differently? What does this make you think about?]

## Real-World Relevance
[More detailed than apprentice level. Reference a real CVE, a disclosed HackerOne report, or a known breach if applicable.]

Example: "This technique mirrors CVE-XXXX-XXXX in [product], where a UNION-based injection in a search endpoint allowed unauthenticated extraction of the users table. HackerOne report #XXXXXX documents a near-identical pattern in a production SaaS app."


## Connections to My Own Projects
[Does this relate to anything in subscription-manager or your other work? Even a "I checked my own app for this and here's what I found" adds enormous credibility.]

## Takeaway
[2–3 sentences. What would you tell a developer on your team about this vulnerability?]