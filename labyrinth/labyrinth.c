#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <testkit.h>
#include "labyrinth.h"

void printUsage() {
    printf("Usage:\n");
    printf("  labyrinth --map map.txt --player id\n");
    printf("  labyrinth -m map.txt -p id\n");
    printf("  labyrinth --map map.txt --player id --move direction\n");
    printf("  labyrinth --version\n");
}

bool isValidPlayer(char playerId) {
    return playerId >= '0' && playerId <= '9';
}

bool loadMap(Labyrinth *labyrinth, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        return false;
    }
    
    int row = 0;
    char line[MAX_COLS + 2]; // +2 for newline and null terminator
    
    while (fgets(line, sizeof(line), file) && row < MAX_ROWS) {
        // Remove newline character if present
        int len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }
        
        // Copy the line to the map
        strncpy(labyrinth->map[row], line, MAX_COLS);
        labyrinth->map[row][MAX_COLS - 1] = '\0'; // Ensure null termination
        
        if (row == 0) {
            labyrinth->cols = len;
        }
        row++;
    }
    
    labyrinth->rows = row;
    fclose(file);
    
    return row > 0;
}

Position findPlayer(Labyrinth *labyrinth, char playerId) {
    Position pos = {-1, -1};
    
    for (int row = 0; row < labyrinth->rows; row++) {
        for (int col = 0; col < labyrinth->cols; col++) {
            if (labyrinth->map[row][col] == playerId) {
                pos.row = row;
                pos.col = col;
                return pos;
            }
        }
    }
    
    return pos;
}

Position findFirstEmptySpace(Labyrinth *labyrinth) {
    Position pos = {-1, -1};
    
    for (int row = 0; row < labyrinth->rows; row++) {
        for (int col = 0; col < labyrinth->cols; col++) {
            if (isEmptySpace(labyrinth, row, col)) {
                pos.row = row;
                pos.col = col;
                return pos;
            }
        }
    }
    
    return pos;
}

bool isEmptySpace(Labyrinth *labyrinth, int row, int col) {
    // Check bounds
    if (row < 0 || row >= labyrinth->rows || col < 0 || col >= labyrinth->cols) {
        return false;
    }
    
    // Check if the space is empty (represented by '.')
    return labyrinth->map[row][col] == '.';
}

bool movePlayer(Labyrinth *labyrinth, char playerId, const char *direction) {
    Position currentPos = findPlayer(labyrinth, playerId);
    if (currentPos.row == -1) {
        return false; // Player not found
    }
    
    int newRow = currentPos.row;
    int newCol = currentPos.col;
    
    // Determine new position based on direction
    if (strcmp(direction, "up") == 0) {
        newRow--;
    } else if (strcmp(direction, "down") == 0) {
        newRow++;
    } else if (strcmp(direction, "left") == 0) {
        newCol--;
    } else if (strcmp(direction, "right") == 0) {
        newCol++;
    } else {
        return false; // Invalid direction
    }
    
    // Check if new position is valid and empty
    if (!isEmptySpace(labyrinth, newRow, newCol)) {
        return false; // Cannot move to this position
    }
    
    // Move the player
    labyrinth->map[currentPos.row][currentPos.col] = '.'; // Clear old position
    labyrinth->map[newRow][newCol] = playerId; // Set new position
    
    return true;
}

bool saveMap(Labyrinth *labyrinth, const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        return false;
    }
    
    for (int row = 0; row < labyrinth->rows; row++) {
        fprintf(file, "%s\n", labyrinth->map[row]);
    }
    
    fclose(file);
    return true;
}

// Check if all empty spaces are connected using DFS
void dfs(Labyrinth *labyrinth, int row, int col, bool visited[MAX_ROWS][MAX_COLS]) {
    // Check bounds and if already visited
    if (row < 0 || row >= labyrinth->rows || col < 0 || col >= labyrinth->cols || visited[row][col]) {
        return;
    }
    
    // Only visit empty spaces
    if (labyrinth->map[row][col] != '.') {
        return;
    }
    
    // Mark as visited
    visited[row][col] = true;
    
    // Recursively visit all adjacent cells
    dfs(labyrinth, row - 1, col, visited); // up
    dfs(labyrinth, row + 1, col, visited); // down
    dfs(labyrinth, row, col - 1, visited); // left
    dfs(labyrinth, row, col + 1, visited); // right
}

bool isConnected(Labyrinth *labyrinth) {
    bool visited[MAX_ROWS][MAX_COLS];
    
    // Initialize visited array
    for (int i = 0; i < MAX_ROWS; i++) {
        for (int j = 0; j < MAX_COLS; j++) {
            visited[i][j] = false;
        }
    }
    
    // Find the first empty space to start DFS
    Position firstEmpty = findFirstEmptySpace(labyrinth);
    if (firstEmpty.row == -1) {
        return true; // No empty spaces, trivially connected
    }
    
    // Perform DFS from the first empty space
    dfs(labyrinth, firstEmpty.row, firstEmpty.col, visited);
    
    // Check if all empty spaces were visited
    for (int row = 0; row < labyrinth->rows; row++) {
        for (int col = 0; col < labyrinth->cols; col++) {
            if (labyrinth->map[row][col] == '.' && !visited[row][col]) {
                return false; // Found an unvisited empty space
            }
        }
    }
    
    return true;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }
    
    // Handle version flag
    if (strcmp(argv[1], "--version") == 0) {
        if (argc != 2) {
            return 1;
        }
        printf("%s\n", VERSION_INFO);
        return 0;
    }
    
    // Parse command line arguments
    char *mapFile = NULL;
    char playerId = '\0';
    char *moveDirection = NULL;
    
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--map") == 0 || strcmp(argv[i], "-m") == 0) && i + 1 < argc) {
            mapFile = argv[++i];
        } else if ((strcmp(argv[i], "--player") == 0 || strcmp(argv[i], "-p") == 0) && i + 1 < argc) {
            playerId = argv[++i][0];
        } else if (strcmp(argv[i], "--move") == 0 && i + 1 < argc) {
            moveDirection = argv[++i];
        } else {
            printUsage();
            return 1;
        }
    }
    
    // Validate required arguments
    if (!mapFile || playerId == '\0') {
        printUsage();
        return 1;
    }
    
    if (!isValidPlayer(playerId)) {
        return 1;
    }
    
    // Load the map
    Labyrinth labyrinth;
    if (!loadMap(&labyrinth, mapFile)) {
        return 1;
    }
    
    // Find player position
    Position playerPos = findPlayer(&labyrinth, playerId);
    if (playerPos.row == -1) {
        // Player not found, place at first empty space
        Position emptyPos = findFirstEmptySpace(&labyrinth);
        if (emptyPos.row == -1) {
            return 1; // No empty space available
        }
        labyrinth.map[emptyPos.row][emptyPos.col] = playerId;
        playerPos = emptyPos;
    }
    
    // Handle move command
    if (moveDirection) {
        if (!movePlayer(&labyrinth, playerId, moveDirection)) {
            return 1;
        }
    }
    
    // Save the map
    if (!saveMap(&labyrinth, mapFile)) {
        return 1;
    }
    
    return 0;
}