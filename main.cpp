/// @file main.cpp
/// @brief Main entry point for the Bignum application.
///
/// This file contains the main function, which provides a command-line interface for
/// encrypting and decrypting text using the Bignum class and RSA.

#include <iostream>
#include <string>
#include "bignum.hpp"

/// @brief Main function providing encryption and decryption functionality.
///
/// The application supports two commands:
/// - `e`: Encrypts input text using RSA encryption.
/// - `d`: Decrypts encrypted text using RSA decryption.
///
/// @param argc Number of command-line arguments.
/// @param argv Array of command-line arguments.
/// @return Exit status of the application.
int main(int argc, char *argv[])
{
    // Ensure a command is provided.
    if (argc < 2)
    {
        std::cout << "Error: No command provided" << std::endl;
        return 0;
    }

    std::string command = argv[1]; ///< Command input: either "e" for encrypt or "d" for decrypt.
    Bignum bignum; ///< Bignum instance for performing encryption and decryption.

    if (command == "e")
    {
        /// @brief Handles encryption of input text.

        std::string to_encrypt, line;
        while (std::getline(std::cin, line))
        {
            to_encrypt += line + "\n";
        }

        if (to_encrypt.empty())
        {
            std::cout << "Error: No text to encrypt" << std::endl;
            return 0;
        }

        // Perform encryption and output results.
        auto encrypted_lines = bignum.large_encrypt(to_encrypt);
        for (size_t i = 0; i < encrypted_lines.size(); i++)
        {
            const auto &encrypted = encrypted_lines[i];
            std::cout << encrypted.first << "\n"
                      << encrypted.second << std::endl;
        }
    }
    else if (command == "d")
    {
        /// @brief Handles decryption of encrypted input text.

        std::vector<std::pair<std::string, std::string>> encrypted_lines; ///< Vector to store encrypted pairs.
        std::string first, second;

        while (std::getline(std::cin, first) && std::getline(std::cin, second))
        {
            encrypted_lines.emplace_back(first, second);
        }

        if (encrypted_lines.empty())
        {
            std::cout << "Error: No values to decrypt" << std::endl;
            return 0;
        }

        // Perform decryption and output results.
        size_t i = 0;
        for (const auto &encrypted : encrypted_lines)
        {
            std::string decrypted = bignum.large_decrypt(encrypted.first, encrypted.second);
            if (i < encrypted_lines.size() - 1)
                std::cout << decrypted << "\n";
            else
                std::cout << decrypted << std::endl;
            i += 1;
        }
    }
    else
    {
        /// @brief Handles unsupported commands.

        std::cout << "Error: Unsupported command" << std::endl;
        return 0;
    }

    return 0;
}
