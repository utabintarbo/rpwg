# ? Robert Costello 2018
# MIT License. Attribution is appreciated.


#! /usr/bin/python

import string, hashlib

global charSet

specialChars = '@#$&*%?='   # This can be expanded to include other chars. I limited it to those usable at my current job.
charSet = string.ascii_uppercase + string.digits + string.ascii_lowercase + specialChars


def repeatable_random(seed):
    ''' from https://stackoverflow.com/questions/9023660/ '''
    while True:
        #hashed = hashlib.md5(seed).digest()
        hashed = hashlib.sha512(seed).digest()
        for c in hashed:
            yield ord(c)

def checkPW(pw, passon3=0, initLetter=1):
    '''
        function to check a password for the common requirements of an uppercase letter, a lowercase letter,
        a digit, and a special character (defined above).

        if initLetter is true (non-zero), then the password has to start with a letter. default is true.

        If passon3 in true (non-zero), then the password will check good on 3 of the 4 params. default is false.
    '''
    import string

    # requirements
    ucase = False
    lcase = False
    number = False
    special = False
    passed = [0,0,0,0]

    for c in pw:
        if c in string.ascii_uppercase:
            ucase = True
            passed[0] = 1
        if c in string.ascii_lowercase:
            lcase = True
            passed[1] = 1
        if c in string.digits:
            number = True
            passed[2] = 1
        if c in specialChars:
            special = True
            passed[3] = 1
    if initLetter:
        if pw[0] in string.ascii_letters and ucase and lcase and number and special:
            return True
        else:
            return False
    if ucase and lcase and number and special:
        return True
    elif passon3 and sum(passed) >= 3:
        return True
    else:
        return False

def makePassword(usrName,domain,passphrase,pin=0,length=10):
    '''
    Creates a random-looking, but repeatable, password from given parameters.
    PIN and passphrase are the main security parameters.

    usrName = login name used on the site
    domain = top-level domain fot the website (basically eveything between th "//" and the next "/"
    passphrase = an easily remembered, but not easily guessed phrase. Length is kinda irrelvant, mostly.
    pin = a PIN number, preferably 4 (or more) digits, just like every other PIN (Default = 0)
    length = desired password length (default = 10)
    '''
    from collections import deque

    import string, base64, hashlib

    passOn3 = 0 # change if only 3 of the 4 requirements is necessary
    # set char set by rotating to the left #pin chars
    d_char = deque(charSet)
    d_char.rotate(int(pin))
    # determine seeding by adding together the numerical value of the PIN with the hex hashes of the
    # pass phrase, top-level domain, and username
    seeding = hex(int(pin) + int(hashlib.sha512(passphrase).hexdigest(),16)+int(hashlib.sha512(domain).hexdigest(),16)+int(hashlib.sha512(usrName).hexdigest(),16))[2:-1]
    # print "seed = %s"%seeding
    pw = '' # empty password

    for i in repeatable_random(seeding):
        # grab the i'th char in the d_char list/deque and append it to pw if it is not a repeat
        if not len(pw):
            pw = pw + d_char[i%len(charSet)]
        elif d_char[i%len(charSet)] != pw[-1]:
            pw = pw + d_char[i%len(charSet)]
        # rotate deque i chars
        # (fwiw, this doesn't really change the strength of the generated password - i just thought i'd add a potential 'wrinkle' for customization)
        d_char.rotate(i)
        if len(pw) == length and checkPW(pw, passOn3):
            break
        else:
            if len(pw) == length:
                # if requirements are not met, drop first char and re-run until met
                pw = pw[1:]

    return pw

def getInfo():
    user = raw_input("Enter username: ")
    TLD = raw_input("Enter domain: ")
    PIN = raw_input("Enter PIN: ")
    pass_phrase = raw_input("Enter pass phrase: ")
    pw_len = raw_input("password length (10):")
    if not pw_len:
        length = 10
    else:
        length = int(pw_len)

    return user, TLD, pass_phrase, PIN, length

def main():
    print "\n\n"
    user, TLD, pass_phrase, PIN, pw_len = getInfo()
    password = makePassword(user,TLD,pass_phrase,PIN,pw_len)

    print "\n\n"
    print "Username = %s\nDomain = %s\nPass Phrase = %s\nPIN = %s\n"%(user,TLD,pass_phrase,PIN)
    print "Password = " + password

if __name__ == '__main__':
    main()
