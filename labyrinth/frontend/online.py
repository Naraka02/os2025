#!/usr/bin/env python3
# Written by Claude 3.7


import argparse
import os
import subprocess
import sys
import tempfile
import shutil
import socket
import threading
import time
from pathlib import Path

try:
    import paramiko
except ImportError:
    print("Error: This script requires the paramiko library.")
    print("Please install it using: pip install paramiko")
    sys.exit(1)


def find_labyrinth_executable():
    current_dir = Path.cwd()

    # Search upward
    dir_to_check = current_dir
    while dir_to_check != dir_to_check.parent:  # Until reaching root directory
        executable = dir_to_check / "labyrinth"
        if executable.exists() and os.access(executable, os.X_OK):
            return executable
        dir_to_check = dir_to_check.parent

    # Recursively search downward
    for root, dirs, files in os.walk(current_dir):
        if "labyrinth" in files:
            executable = Path(root) / "labyrinth"
            if os.access(executable, os.X_OK):
                return executable

    return None


class LabyrinthServer(paramiko.ServerInterface):
    def __init__(self, map_file):
        self.map_file = map_file
        self.temp_map_file = create_temp_map_file(map_file)
        self.labyrinth_path = find_labyrinth_executable()
        self.players = {}  # {username: player_id}
        self.lock = threading.Lock()

        # Read the original map to determine available player positions
        self.available_player_ids = self.get_available_player_ids()

        if not self.labyrinth_path:
            print("Error: Could not find labyrinth executable")
            sys.exit(1)

        print(f"Available player positions in map: {self.available_player_ids}")

    def get_available_player_ids(self):
        """Read the map file and determine which player IDs (0-9) are available."""
        available_ids = set()
        try:
            with open(self.map_file, "r") as f:
                map_content = f.read()
                # Check for each digit 0-9 in the map
                for digit in range(10):  # 0-9
                    if str(digit) in map_content:
                        available_ids.add(digit)
        except Exception as e:
            print(f"Error reading map file: {e}")
        return available_ids

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_none(self, username):
        # Always accept authentication - we'll check for available positions later
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "none"

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def create_temp_map_file(original_map_file):
    fd, temp_path = tempfile.mkstemp(suffix=".txt", prefix="labyrinth_map_")
    os.close(fd)

    # Copy original map to temporary file
    shutil.copy2(original_map_file, temp_path)
    return temp_path


def get_map_state(labyrinth_path, map_file):
    result = subprocess.run([str(labyrinth_path), "--map", map_file, "--player", "0"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error getting map state: {result.stderr}")
    return result.stdout.strip().split("\n")


def move_player(labyrinth_path, map_file, player_id, direction):
    result = subprocess.run([str(labyrinth_path), "--map", map_file, "--player", str(player_id), "--move", direction], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error moving player {player_id}: {result.stderr}")
    return result.returncode == 0


def handle_client(client, server, addr, shutdown_flag):
    try:
        transport = paramiko.Transport(client)
        host_key = paramiko.RSAKey.generate(2048)
        transport.add_server_key(host_key)

        transport.start_server(server=server)

        channel = transport.accept(20)
        if channel is None:
            print("No channel established")
            return

        # Get username from the transport
        username = transport.get_username()

        # Check if there are available player positions
        with server.lock:
            # If user is already connected, use their existing ID
            if username in server.players:
                player_id = server.players[username]
            else:
                # Check for available positions
                available_ids = server.available_player_ids - set(server.players.values())
                if not available_ids:
                    # No available positions - send error message and close
                    channel.send("\033[H\033[J")  # Clear screen
                    channel.send("Sorry, the game is full! All player positions are taken.\r\n")
                    channel.send("Please try again later when a spot becomes available.\r\n")
                    time.sleep(3)  # Give user time to read the message
                    channel.close()
                    return

                # Assign the lowest available ID
                player_id = min(available_ids)
                server.players[username] = player_id
                print(f"Player {username} connected with ID {player_id}")

        # Send welcome message
        channel.send(f"Welcome to Labyrinth Online! You are player {player_id}.\r\n")
        channel.send("Use WASD keys to move. Press Q to quit.\r\n\r\n")

        # Get initial map state and display it
        with server.lock:
            current_map_state = get_map_state(server.labyrinth_path, server.temp_map_file)

        # Display initial map
        display_map(channel, current_map_state)

        # Game loop for this client
        while not shutdown_flag.is_set():
            # Check if channel is still open
            if not channel.get_transport() or not channel.get_transport().is_active():
                break

            # Wait for input
            if not channel.recv_ready():
                # Check if map has changed due to other players
                if not shutdown_flag.is_set():  # Only check if not shutting down
                    try:
                        with server.lock:
                            new_map_state = get_map_state(server.labyrinth_path, server.temp_map_file)

                        # Only update if the map has changed
                        if new_map_state != current_map_state:
                            current_map_state = new_map_state
                            display_map(channel, current_map_state)
                    except Exception as e:
                        if not shutdown_flag.is_set():  # Only print if not shutting down
                            print(f"Error updating map: {e}")
                        break

                time.sleep(0.1)
                continue

            try:
                data = channel.recv(1)
                if not data:
                    break

                key = data.decode("utf-8").lower()

                # Process movement
                moved = False
                if not shutdown_flag.is_set():  # Only process if not shutting down
                    with server.lock:
                        if key == "w":
                            moved = move_player(server.labyrinth_path, server.temp_map_file, player_id, "up")
                        elif key == "a":
                            moved = move_player(server.labyrinth_path, server.temp_map_file, player_id, "left")
                        elif key == "s":
                            moved = move_player(server.labyrinth_path, server.temp_map_file, player_id, "down")
                        elif key == "d":
                            moved = move_player(server.labyrinth_path, server.temp_map_file, player_id, "right")
                        elif key == "q":
                            break

                    # Update map state if player moved
                    if moved:
                        with server.lock:
                            current_map_state = get_map_state(server.labyrinth_path, server.temp_map_file)
                        display_map(channel, current_map_state)
            except Exception as e:
                if not shutdown_flag.is_set():  # Only print if not shutting down
                    print(f"Error processing input: {e}")
                break

        # If we're shutting down, notify the user
        if shutdown_flag.is_set() and channel.get_transport() and channel.get_transport().is_active():
            try:
                channel.send("\r\n\r\nServer is shutting down. Thank you for playing!\r\n")
            except:
                pass

    except Exception as e:
        if not shutdown_flag.is_set():  # Only print if not shutting down
            print(f"Error handling client: {e}")
    finally:
        try:
            # Remove player from active players
            with server.lock:
                if username in server.players:
                    print(f"Player {username} (ID: {server.players[username]}) disconnected")
                    del server.players[username]

            transport.close()
        except:
            pass


def display_map(channel, map_state):
    # Clear screen and display map
    channel.send("\033[H\033[J")  # ANSI escape sequence to clear screen
    for line in map_state:
        channel.send(line + "\r\n")

    channel.send("\r\nUse WASD keys to move. Press Q to quit.\r\n")


def main():
    parser = argparse.ArgumentParser(description="Online multiplayer labyrinth game server")
    parser.add_argument("--map", "-m", required=True, help="Path to the map file")
    parser.add_argument("--port", "-p", type=int, default=4399, help="Port to listen on (default: 4399)")
    args = parser.parse_args()

    if not os.path.exists(args.map):
        print(f"Error: Map file '{args.map}' not found")
        return

    # Create server socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Track active client threads
    active_threads = []
    shutdown_flag = threading.Event()

    try:
        sock.bind(("0.0.0.0", args.port))
    except Exception as e:
        print(f"Error binding to port {args.port}: {e}")
        return

    # Create server instance
    server = LabyrinthServer(args.map)
    temp_map_file = server.temp_map_file  # Store reference to temp file

    # Modified handle_client function that checks shutdown flag
    def handle_client_with_shutdown(client, server, addr):
        thread = threading.Thread(target=handle_client, args=(client, server, addr, shutdown_flag))
        thread.daemon = True  # Make thread a daemon so it exits when main thread exits
        thread.start()
        active_threads.append(thread)

    try:
        sock.listen(100)
        print(f"Labyrinth server listening on port {args.port}...")
        print(f"Connect using: ssh -p {args.port} -o StrictHostKeyChecking=no <username>@localhost")

        # Set socket to non-blocking mode
        sock.settimeout(1.0)  # 1 second timeout to check for shutdown flag

        while not shutdown_flag.is_set():
            try:
                client, addr = sock.accept()
                print(f"Connection from {addr[0]}:{addr[1]}")
                handle_client_with_shutdown(client, server, addr)
            except socket.timeout:
                # This is expected, just continue and check shutdown flag
                continue
            except Exception as e:
                if not shutdown_flag.is_set():  # Only print if not shutting down
                    print(f"Error accepting connection: {e}")

    except KeyboardInterrupt:
        print("\nServer shutting down gracefully...")
        shutdown_flag.set()  # Signal all threads to stop
    except Exception as e:
        print(f"Error: {e}")
        shutdown_flag.set()  # Signal all threads to stop
    finally:
        # Clean up
        print("Cleaning up resources...")

        # Close socket first
        try:
            sock.close()
            print("Socket closed.")
        except Exception as e:
            print(f"Error closing socket: {e}")

        # Wait for client threads to finish (with timeout)
        print("Waiting for client connections to close...")
        for thread in active_threads:
            thread.join(timeout=2.0)  # Wait up to 2 seconds for each thread

        # Remove temporary file
        try:
            if os.path.exists(temp_map_file):
                os.unlink(temp_map_file)
                print(f"Temporary map file {temp_map_file} removed.")
        except Exception as e:
            print(f"Warning: Could not remove temporary file: {e}")

        print("Server shutdown complete.")


if __name__ == "__main__":
    main()
