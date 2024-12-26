/// @file bignum.hpp
/// @brief Declaration of the Bignum class for handling large integer operations.
///
/// This header file defines the Bignum class, which provides methods for large integer
/// arithmetic, including addition, subtraction, multiplication, division, and modular
/// exponentiation. The class is optimized for cryptographic applications and supports
/// operations such as encryption and decryption using RSA.

#include <string>
#include <vector>
#include <utility>

/// @class Bignum
/// @brief A class for representing and manipulating large integers.
class Bignum
{
private:
    std::vector<int> bignum_vector; ///< Internal representation of the large integer as a vector of digits.

    static const std::string rsa_n; ///< RSA modulus (placeholder).
    static const std::string rsa_e; ///< RSA public exponent (placeholder).
    static const std::string rsa_d; ///< RSA private exponent (placeholder).
    static const size_t MAX_CHARS_PER_CHUNK; ///< Maximum characters allowed per chunk in encryption.

    static const Bignum public_mod; ///< Bignum representation of RSA modulus.
    static const Bignum public_exp; ///< Bignum representation of RSA public exponent.
    static const Bignum priv_exp; ///< Bignum representation of RSA private exponent.

    /// @brief Removes leading zeros from the Bignum.
    void remove_excess();

public:
    /// @brief Default constructor that initializes an empty Bignum.
    Bignum();

    /// @brief Constructor that initializes a Bignum from a string representation.
    /// @param string_num A string representing a large integer.
    Bignum(const std::string &string_num);

    /// @brief Equality operator for Bignum.
    /// @param other The Bignum to compare with.
    /// @return True if both Bignums are equal, false otherwise.
    bool operator==(const Bignum &other) const;

    /// @brief Less-than operator for Bignum.
    /// @param other The Bignum to compare with.
    /// @return True if this Bignum is less than the other, false otherwise.
    bool operator<(const Bignum &other) const;

    /// @brief Greater-than operator for Bignum.
    /// @param other The Bignum to compare with.
    /// @return True if this Bignum is greater than the other, false otherwise.
    bool operator>(const Bignum &other) const;

    /// @brief Subtraction operator for Bignum.
    /// @param other The Bignum to subtract from this Bignum.
    /// @return A new Bignum representing the result of the subtraction.
    Bignum operator-(const Bignum &other) const;

    /// @brief Multiplication operator for Bignum.
    /// @param other The Bignum to multiply with this Bignum.
    /// @return A new Bignum representing the product.
    Bignum operator*(const Bignum &other) const;

    /// @brief Division operator for Bignum.
    /// @param other The Bignum to divide this Bignum by.
    /// @return A new Bignum representing the quotient.
    Bignum operator/(const Bignum &other) const;

    /// @brief Modulo operator for Bignum.
    /// @param other The Bignum to compute the modulo with.
    /// @return A new Bignum representing the remainder.
    Bignum operator%(const Bignum &other) const;

    /// @brief Modular exponentiation using the Bignum class.
    /// @param base The base Bignum.
    /// @param exponent The exponent Bignum.
    /// @param modulus The modulus Bignum.
    /// @return A new Bignum representing the modular exponentiation result.
    Bignum mod_exponent(const Bignum &base, const Bignum &exponent, const Bignum &modulus) const;

    /// @brief Converts the Bignum to a string representation.
    /// @return A string representation of the Bignum.
    std::string to_string() const;

    /// @brief Converts a string to a Bignum.
    /// @param str The string to convert.
    /// @return A Bignum representing the input string.
    Bignum string_to_bignum(const std::string &str) const;

    /// @brief Converts a Bignum to a string.
    /// @param bignum The Bignum to convert.
    /// @return A string representation of the Bignum.
    std::string bignum_to_string(const Bignum &bignum) const;

    /// @brief Pads a string with spaces and a line number.
    /// @param input The input string to pad.
    /// @param line_num The line number to include in the padding.
    /// @return A padded string.
    std::string padding(const std::string &input, int line_num) const;

    /// @brief Encrypts a large text using RSA in chunks.
    /// @param text The text to encrypt.
    /// @return A vector of encrypted pairs of strings.
    std::vector<std::pair<std::string, std::string>> large_encrypt(const std::string &text) const;

    /// @brief Decrypts a large text using RSA.
    /// @param first The first part of the encrypted string.
    /// @param second The second part of the encrypted string.
    /// @return The decrypted string.
    std::string large_decrypt(const std::string &first, const std::string &second) const;
};
