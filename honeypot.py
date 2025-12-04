import socket
import threading
import time
import paramiko
import sys



# use:
# client: ssh [username]@localhost -p [portnumber]
# example: ssh joy67@localhost -p 8129

# running server: python honeypot.py -p [portnumber]
# example: python honeypot.py -p 8129


# Configuration
MAX_ATTEMPTS = 5 #TODO remember to change this 2 to 5 when submitting
IDLE_TIMEOUT = 60
FAKE_FILE_SYSTEM = {}
USERNAMES = []
global last_interaction
# Load usernames from a file
def load_usernames():
    try:
        with open("usernames.txt", "r") as f:
            for line in f:
                USERNAMES.append(line.strip())
    except FileNotFoundError:
        print("Username file 'usernames.txt' not found. Exiting.")
        sys.exit(1)

class SSHHoneypotServer(paramiko.ServerInterface):
    def __init__(self, attempts_tracker):
        self.event = threading.Event()
        self.username = None
        self.attempts_tracker = attempts_tracker

    def check_auth_password(self, username, password):
        self.username = username

        if username not in USERNAMES:
            print(f"Invalid username: {username}. Connection denied.")
            return paramiko.AUTH_FAILED

        if username not in self.attempts_tracker:
            self.attempts_tracker[username] = 0

        self.attempts_tracker[username] += 1

        if self.attempts_tracker[username] > MAX_ATTEMPTS:
            print(f"Access granted to {username} after {MAX_ATTEMPTS} attempts.")
            return paramiko.AUTH_SUCCESSFUL

        print(f"Failed attempt {self.attempts_tracker[username]} for {username}.")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        print("Shell request received. Starting fake shell session.")
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        print("PTY request received. Granting PTY.")
        return True

# Command handler for the shell session
def handle_command(command, channel):
    global FAKE_FILE_SYSTEM
    if command == "ls":
        files = " ".join(FAKE_FILE_SYSTEM.keys())
        channel.sendall((files if files else "\r\n") + "\r\n")
    elif command.startswith("echo") and ">" in command: # echo "content" > file.txt
        try:
            parts = command.split(">", 1)
            content = parts[0].replace("echo", "").strip().strip('"')
            filename = parts[1].strip()
            if filename.endswith(".txt"):
                FAKE_FILE_SYSTEM[filename] = content
                channel.sendall("")
            else:
                channel.sendall("Unknown file extension\r\n")
        except Exception as e:
            channel.sendall(f"Error processing echo: {e}\r\n")   
    elif command.startswith("echo"): # echo "content" prints content
        parts = command.split(" ", 1)
        if len(parts) != 2:
            channel.sendall("Missing content\r\n")
        else:
            content = parts[1].strip().strip('"')
            channel.sendall(content + "\r\n")
    elif command.startswith("cp"): # cp source.txt dest.txt copies text in source to dest
        parts = command.split(" ")
        if len(parts) < 3:
            channel.sendall("Missing source or destination file\r\n")
        elif len(parts) > 3:
            channel.sendall("Invalid command ; use: cp 'source-file' 'destination-file' \r\n")
        else:
            source, dest = parts[1], parts[2]
            if source not in FAKE_FILE_SYSTEM:
                channel.sendall(f"{source} not found\r\n")
            else:
                 if source.endswith(".txt") & dest.endswith(".txt"):
                    FAKE_FILE_SYSTEM[dest] = FAKE_FILE_SYSTEM[source]
                    channel.sendall("")
                 else:
                    channel.sendall("Unknown file extension\r\n")
                
    elif command.startswith("rm"): # rm file.txt deletes file
        parts = command.split(" ", 1)
        if len(parts) < 2:
            channel.sendall("Missing file name\r\n")
        elif len(parts) > 2:
            channel.sendall("Invalid command ; use: rm 'filename' \r\n")
        else:
            filename = parts[1].strip()
            if not filename.endswith(".txt"):
                channel.sendall("Unknown file extension\r\n")
            if filename not in FAKE_FILE_SYSTEM:
                channel.sendall(f"{filename} not found\r\n")
            else:
                del FAKE_FILE_SYSTEM[filename]
                channel.sendall("") 
                                
    elif command.startswith("cat"): # cat file.txt prints file content
        parts = command.split(" ", 1)
        if len(parts) < 2:
            channel.sendall("Missing file name\r\n")
        elif len(parts) > 2:
            channel.sendall("Invalid command ; use: cat 'filename' \r\n")
        else:
            filename = parts[1].strip() 
            if not filename.endswith(".txt"):
                channel.sendall("Unknown file extension\r\n")
            elif filename not in FAKE_FILE_SYSTEM:
                channel.sendall(f"File {filename} not found\r\n")
            else:
                channel.sendall(FAKE_FILE_SYSTEM[filename] + "\r\n")
                
    elif command == "exit": # exit closes the shell session
        channel.sendall("Exiting....\r\n")
        FAKE_FILE_SYSTEM.clear()
        return False
    else:
        channel.sendall(f"Command {command} not found\r\n")
    return True

# Shell session manager
def shell_session(channel, username):
    global FAKE_FILE_SYSTEM
    channel.sendall(f"Welcome to {username}@honeypot:/$\r\n")
    last_interaction = time.time()
    buffer = ""
    session_active = True

    while session_active:
        current_time = time.time()
        TimeDiff = current_time - last_interaction
        if TimeDiff > IDLE_TIMEOUT:
            channel.sendall("Connection timed out. Idle for " + str(int(TimeDiff)) + " seconds. Closing session.\r\n")
            FAKE_FILE_SYSTEM.clear
            session_active = False
            break
        last_interaction = time.time()
        try:
            channel.sendall(f"{username}@honeypot:/$ ")
            while session_active:
                print(TimeDiff)
                if not session_active:
                    break

                char = channel.recv(1).decode()
                if not char:
                    session_active = False
                    break
    
                if char in ("\r", "\n"):
                    channel.sendall("\r\n")
                    command = buffer.strip()
                    buffer = ""
                    session_active = handle_command(command, channel)
                    break
                elif char == "\x7f":
                    if len(buffer) > 0:
                        buffer = buffer[:-1]
                        channel.sendall("\b \b")
                else:
                    buffer += char
                    channel.sendall(char.encode())
        except Exception as e:
            print(f"Error in shell session: {e}")
            break
    FAKE_FILE_SYSTEM.clear
    channel.close()

# Connection handler
def handle_connection(client, addr):
    transport = paramiko.Transport(client)
    transport.add_server_key(paramiko.RSAKey.generate(2048))
    server = SSHHoneypotServer(attempts_tracker={})

    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            print("No channel.")
            return

        print(f"Connection established from {addr}")
        server.event.wait(10)
        if not server.event.is_set():
            print("Shell request not received.")
            channel.close()
            return

        shell_session(channel, server.username)

    except Exception as e:
        print(f"Error during connection handling: {e}")
    finally:
        FAKE_FILE_SYSTEM.clear
        transport.close()

def main():
    if len(sys.argv) != 3 or sys.argv[1] != "-p":
        print("Usage: python honeypot.py -p [port]")
        sys.exit(1)

    port = int(sys.argv[2])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(100)

    print(f"Honeypot listening on port {port}")

    while True:
        client, addr = server_socket.accept()
        threading.Thread(target=handle_connection, args=(client, addr)).start()

if __name__ == "__main__":
    load_usernames()  # Ensure usernames are loaded before starting
    main()