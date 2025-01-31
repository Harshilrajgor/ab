#include <stdio.h>
#include <string.h>

// Function to calculate and append parity bits
void calculateVRC(char data[][9], int rows, char parityData[][10], int evenParity) {
    for (int i = 0; i < rows; i++) {
        int count = 0;

        // Count the number of 1s in the block
        for (int j = 0; j < 8; j++) {
            if (data[i][j] == '1') {
                count++;
            }
        }

        // Determine parity bit
        if (evenParity) {
            // Even parity: append 0 if count is even, 1 if odd
            parityData[i][8] = (count % 2 == 0) ? '0' : '1';
        } else {
            // Odd parity: append 1 if count is even, 0 if odd
            parityData[i][8] = (count % 2 == 0) ? '1' : '0';
        }

        // Append parity bit and terminate the string
        strncpy(parityData[i], data[i], 8);
        parityData[i][9] = '\0';
    }
}

// Function to verify parity at the receiver
int verifyVRC(char parityData[][10], int rows, int evenParity) {
    for (int i = 0; i < rows; i++) {
        int count = 0;

        // Count the number of 1s in the block, including the parity bit
        for (int j = 0; j < 9; j++) {
            if (parityData[i][j] == '1') {
                count++;
            }
        }

        // Check if parity matches the chosen parity type
        if ((evenParity && count % 2 != 0) || (!evenParity && count % 2 == 0)) {
            return 0; // Parity check failed
        }
    }
    return 1; // Parity check passed
}

int main() {
    char data[4][9] = { // Input binary data blocks (8 bits each)
        "11001101",
        "10101010",
        "11110000",
        "00001111"
    };

    char parityData[4][10];
    int rows = 4;

    // Calculate and append even parity bits
    calculateVRC(data, rows, parityData, 1); // Use 1 for even parity

    printf("Data with Parity Bits (Even Parity):\n");
    for (int i = 0; i < rows; i++) {
        printf("%s\n", parityData[i]);
    }

    // Verify parity at the receiver
    if (verifyVRC(parityData, rows, 1)) {
        printf("Parity Check Passed: No Errors Detected.\n");
    } else {
        printf("Parity Check Failed: Errors Detected.\n");
    }

    return 0;
}
