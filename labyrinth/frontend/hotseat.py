#!/usr/bin/env python3
# Written by Claude 3.7

import argparse
import curses
import os
import subprocess
import sys
import tempfile
import shutil
from pathlib import Path


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


def run_game(stdscr, map_file):
    labyrinth_path = find_labyrinth_executable()
    if not labyrinth_path:
        print("Error: Could not find labyrinth executable")
        return

    # Check if map contains positions for players 0 and 1
    if not check_player_positions(map_file, [0, 1]):
        print("Error: Map must contain positions for players 0 and 1")
        return

    # Create temporary map file
    temp_map_file = create_temp_map_file(map_file)

    curses.curs_set(0)  # Hide cursor
    stdscr.clear()

    # Initialize players
    player1_id = 0
    player2_id = 1

    # Get initial map state
    map_state = get_map_state(labyrinth_path, temp_map_file)

    # Display initial map and controls
    display_map(stdscr, map_state)

    # Display control instructions
    stdscr.addstr(len(map_state) + 2, 0, "Player 1: WASD to move")
    stdscr.addstr(len(map_state) + 3, 0, "Player 2: HJKL to move")
    stdscr.addstr(len(map_state) + 4, 0, "Press Q to quit")
    stdscr.refresh()

    # Game main loop
    while True:
        key = stdscr.getch()

        # Player 1 controls (WASD)
        if key == ord("w"):
            move_player(labyrinth_path, temp_map_file, player1_id, "up")
        elif key == ord("a"):
            move_player(labyrinth_path, temp_map_file, player1_id, "left")
        elif key == ord("s"):
            move_player(labyrinth_path, temp_map_file, player1_id, "down")
        elif key == ord("d"):
            move_player(labyrinth_path, temp_map_file, player1_id, "right")

        # Player 2 controls (HJKL)
        elif key == ord("k"):
            move_player(labyrinth_path, temp_map_file, player2_id, "up")
        elif key == ord("h"):
            move_player(labyrinth_path, temp_map_file, player2_id, "left")
        elif key == ord("j"):
            move_player(labyrinth_path, temp_map_file, player2_id, "down")
        elif key == ord("l"):
            move_player(labyrinth_path, temp_map_file, player2_id, "right")

        # Exit game
        elif key == ord("q"):
            break

        # Update map state and display
        map_state = get_map_state(labyrinth_path, temp_map_file)
        display_map(stdscr, map_state)

        # Redisplay control instructions
        stdscr.addstr(len(map_state) + 2, 0, "Player 1: WASD to move")
        stdscr.addstr(len(map_state) + 3, 0, "Player 2: HJKL to move")
        stdscr.addstr(len(map_state) + 4, 0, "Press Q to quit")
        stdscr.refresh()

    # Clean up temporary files
    try:
        os.unlink(temp_map_file)
    except:
        pass


def create_temp_map_file(original_map_file):
    fd, temp_path = tempfile.mkstemp(suffix=".txt", prefix="labyrinth_map_")
    os.close(fd)

    # Copy original map to temporary file
    shutil.copy2(original_map_file, temp_path)
    return temp_path


def get_map_state(labyrinth_path, map_file):
    print(f"Executing command: {labyrinth_path} --map {map_file} --player 0")
    result = subprocess.run([str(labyrinth_path), "--map", map_file, "--player", "0"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
    return result.stdout.strip().split("\n")


def move_player(labyrinth_path, map_file, player_id, direction):
    print(f"Executing command: {labyrinth_path} --map {map_file} --player {player_id} --move {direction}")
    result = subprocess.run([str(labyrinth_path), "--map", map_file, "--player", str(player_id), "--move", direction], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Movement error: {result.stderr}")


def display_map(stdscr, map_state):
    stdscr.clear()
    for i, line in enumerate(map_state):
        stdscr.addstr(i, 0, line)
    stdscr.refresh()


def check_player_positions(map_file, required_players):
    """Check if the map contains positions for all required players."""
    try:
        with open(map_file, "r") as f:
            map_content = f.read()
            for player_id in required_players:
                if str(player_id) not in map_content:
                    return False
        return True
    except Exception as e:
        print(f"Error reading map file: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Local two-player labyrinth game")
    parser.add_argument("--map", "-m", required=True, help="Path to the map file")
    args = parser.parse_args()

    if not os.path.exists(args.map):
        print(f"Error: Map file '{args.map}' not found")
        return

    # Check if map contains positions for players 0 and 1
    if not check_player_positions(args.map, [0, 1]):
        print("Error: Map must contain positions for players 0 and 1")
        return

    curses.wrapper(run_game, args.map)


if __name__ == "__main__":
    main()
