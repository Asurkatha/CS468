# SSH Honeypot – CS 468 Homework 5

## Overview

This project implements a functional **SSH honeypot server** in Python designed to simulate a vulnerable system and capture brute-force attack behavior.  
The honeypot monitors repeated login attempts against known usernames and grants shell access after exceeding a defined threshold.  
Once logged in, attackers interact with a **fully simulated shell and file system**, allowing controlled command execution and file manipulation.

---

## Features

### Brute-Force Detection
- Tracks login attempts per username.
- Grants access after **more than 5 failed attempts**.
- Rejects unknown usernames.
- Logs attempts to the server console.

---

### SSH Shell Emulation
- SSH protocol implemented using **Paramiko**.
- Presents an authentic shell prompt:
- <username>@honeypot:/$
- Accepts interactive command input.
- Terminates idle sessions after **60 seconds**.

---

### Fake File System

The honeypot simulates an in-memory filesystem supporting the following commands:

| Command | Description |
|--------|-------------|
| `ls` | Lists all files in the current directory |
| `echo "TEXT" > file.txt` | Creates a `.txt` file with specified content |
| `cat file.txt` | Displays file contents |
| `cp source.txt dest.txt` | Copies file contents |
| `rm file.txt` | Deletes a `.txt` file |
| `exit` | Closes the shell session |

**Rules:**
- Only files with the `.txt` extension are supported.
- Other extensions produce:  
  `Unknown file extension`
- Missing files produce:  
  `File <filename> not found`

---

## Requirements

- **Python 3.5+**
- **Paramiko SSH library**

Install with:

bash
pip install paramiko
Input Files

usernames.txt
A file containing valid usernames (one per line) used to simulate brute-force targets.

Running the Honeypot
Start the Server
python honeypot.py -p <port>


Example:

python honeypot.py -p 8129

Connect with SSH

From another terminal:

ssh <username>@localhost -p <port>


## Example:

ssh john@localhost -p 8129


After more than 5 login attempts, shell access is granted automatically.

## Example Shell Session
john@honeypot:/$ ls

john@honeypot:/$ echo "hello world" > sample.txt
john@honeypot:/$ ls
sample.txt

john@honeypot:/$ cat sample.txt
hello world

john@honeypot:/$ cp sample.txt backup.txt
john@honeypot:/$ ls
sample.txt backup.txt

john@honeypot:/$ rm backup.txt
john@honeypot:/$ ls
sample.txt

john@honeypot:/$ exit

Timeout Behavior

If the connected client remains idle for longer than 60 seconds, the honeypot automatically:

Disconnects the session.

Clears the fake file system.

Frees system resources.

File Structure
File	Purpose
honeypot.py	Main SSH honeypot server implementation
usernames.txt	List of legitimate target usernames
README.md	Project documentation
