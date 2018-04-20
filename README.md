# rpwg
Project to create repeatable random-looking passwords using hashes.

The Rationale--

Given my cynical and pessimistic nature, I always worried about the possibility of losing my password database, and having to go through the annoying and tedious password recovery procedures for the umpteen zillion websites for which I have login's.

Then there's the issue of having multiple websites with the same password - even if it is a very secure password, this is Bad Policy. This led me to the idea of having a random-looking password that is generated by an algorithm, and is unique to each login/domain pairing. If you "lose" your password for (given-site.com), you just plug in the login_name, site, PIN, passphrase, and length, at it will faithfully reproduce that lost password (given the same parameters this time as the first time, of course).

The Implementation--

For the record, this is a python script, suitable to run on every platform which has a python interpreter (which is just about all of them). It was developed using python 2.6.6, so it will likely work with almost any v2.X out there (also tested with qpython 2.7.12 on Android and v2.7.9 on Linux).

Since it is a script, there are any number of avenues for customization, the most beneficial of which is adding to the allowable “special characters” (the eight I allowed are those allowed by my current employer).

It should be relatively easy to follow the alleged logic from the docstrings and comments (FWIW, I think I spent more time commenting than coding ;) ).

The Results--

So how good are the passwords generated? Well, I ran them through the Password Strength Checker at http://www.passwordmeter.com/ and “How Secure is My Password” at https://howsecureismypassword.net/ and got similarly good security ratings relative to the examples Steve posted from PWGen (for HSIMP, Steve’s 18 char passwords got a 380 quadrillion year rating vs. 7 quadrillion years for this program, likely due to the limited pool of “special characters” I used). While the difference between 7 and 380 quadrillion years seems like a lot, it is effectively the difference between infinity and infinity * 54.

The Future--

* Allowing for "default" entries (such as username), likely using an .ini file. Dunno if necessary.
* A GUI - this may help me finally get a handle on tKinter
* Migration to python v3 - this may help me finally get a handle on v3
* Something to deal with sites that make you change your password regularly
* ???

Usage--

The CLI implementation uses raw_input to gather username, domain, PIN, passphrase, and password length (with a default of 10). It returns a reiteration of the parameters, along with a random-looking password.

Example:
>python repeatablePWgen.py


Enter username: loginname

Enter domain: facebook.com

Enter PIN: 1003

Enter pass phrase: my dog has fleas

password length (10):




Username = loginname

Domain = facebook.com

Pass Phrase = my dog has fleas

PIN = 1003


Password = HeYwrM3Lc#

