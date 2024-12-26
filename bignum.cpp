/// @file bignum.cpp
/// @brief Implementation of the Bignum class for handling large integer operations.
///
/// This file contains the implementation of the Bignum class, which provides methods
/// for large integer arithmetic, including addition, subtraction, multiplication,
/// division, and modular exponentiation. The class is optimized for cryptographic
/// applications and supports multithreading for certain operations.

#include "bignum.hpp"
#include <stdexcept>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <future>
#include <thread>
#include <mutex>

// Static constants for RSA parameters (placeholders to be replaced with actual values).
const std::string Bignum::rsa_n = "TO_FILL"; ///< RSA modulus
const std::string Bignum::rsa_e = "TO_FILL"; ///< RSA public exponent
const std::string Bignum::rsa_d = "TO_FILL"; ///< RSA private exponent

// Maximum number of characters allowed per chunk in large encryption.
const size_t Bignum::MAX_CHARS_PER_CHUNK = 96;

// Static constants for modular arithmetic using RSA parameters.
const Bignum Bignum::public_mod(Bignum::rsa_n);
const Bignum Bignum::public_exp(Bignum::rsa_e);
const Bignum Bignum::priv_exp(Bignum::rsa_d);

/// @brief Default constructor that initializes an empty Bignum.
Bignum::Bignum() : bignum_vector{} {}

/// @brief Constructor that initializes a Bignum from a string representation.
/// @param string_num A string representing a large integer.
Bignum::Bignum(const std::string &string_num)
{
    for (char ch : string_num)
    {
        bignum_vector.push_back(ch - '0');
    }
}

/// @brief Removes leading zeros from the Bignum.
void Bignum::remove_excess()
{
    while (bignum_vector.size() > 1 && bignum_vector[0] == 0)
    {
        bignum_vector.erase(bignum_vector.begin());
    }
}

/// @brief Equality operator for Bignum.
/// @param other The Bignum to compare with.
/// @return True if both Bignums are equal, false otherwise.
bool Bignum::operator==(const Bignum &other) const
{
    return bignum_vector == other.bignum_vector;
}

/// @brief Less-than operator for Bignum.
/// @param other The Bignum to compare with.
/// @return True if this Bignum is less than the other, false otherwise.
bool Bignum::operator<(const Bignum &other) const
{
    if (bignum_vector.size() != other.bignum_vector.size())
    {
        return bignum_vector.size() < other.bignum_vector.size();
    }
    return std::lexicographical_compare(bignum_vector.begin(), bignum_vector.end(),
                                        other.bignum_vector.begin(), other.bignum_vector.end());
}

/// @brief Greater-than operator for Bignum.
/// @param other The Bignum to compare with.
/// @return True if this Bignum is greater than the other, false otherwise.
bool Bignum::operator>(const Bignum &other) const
{
    return other < *this;
}

/// @brief Subtraction operator for Bignum.
/// @param other The Bignum to subtract from this Bignum.
/// @return A new Bignum representing the result of the subtraction.
Bignum Bignum::operator-(const Bignum &other) const
{
    Bignum difference;
    int borrow = 0;

    const int max_size = std::max(bignum_vector.size(), other.bignum_vector.size());
    difference.bignum_vector.resize(max_size);

    for (int i = bignum_vector.size() - 1, j = other.bignum_vector.size() - 1, k = difference.bignum_vector.size() - 1;
         k >= 0; i--, j--, k--)
    {
        int first_dig = (i >= 0) ? bignum_vector[i] : 0;
        int second_dig = (j >= 0) ? other.bignum_vector[j] : 0;
        int curr_diff = first_dig - second_dig - borrow;

        if (curr_diff < 0)
        {
            curr_diff += 10;
            borrow = 1;
        }
        else
        {
            borrow = 0;
        }

        difference.bignum_vector[k] = curr_diff;
    }

    difference.remove_excess();
    return difference;
}

/// @brief Multiplication operator for Bignum.
/// @param other The Bignum to multiply with this Bignum.
/// @return A new Bignum representing the product.
Bignum Bignum::operator*(const Bignum &other) const
{
    Bignum product;
    const int product_size = bignum_vector.size() + other.bignum_vector.size();
    product.bignum_vector.resize(product_size, 0);

    for (int i = bignum_vector.size() - 1; i >= 0; i--)
    {
        if (bignum_vector[i] == 0)
            continue;

        int carry_over = 0;
        for (int j = other.bignum_vector.size() - 1; j >= 0; j--)
        {
            const long long curr_product = static_cast<long long>(bignum_vector[i]) * other.bignum_vector[j] + product.bignum_vector[i + j + 1] + carry_over;

            product.bignum_vector[i + j + 1] = curr_product % 10;
            carry_over = curr_product / 10;
        }

        product.bignum_vector[i] += carry_over;
    }

    product.remove_excess();
    return product;
}

/// @brief Division operator for Bignum.
/// @param other The Bignum to divide this Bignum by.
/// @return A new Bignum representing the quotient.
Bignum Bignum::operator/(const Bignum &other) const
{
    Bignum quo("0");
    Bignum rem;

    for (const size_t i : bignum_vector)
    {
        rem.bignum_vector.push_back(i);
        while (!rem.bignum_vector.empty() && rem.bignum_vector[0] == 0)
            rem.bignum_vector.erase(rem.bignum_vector.begin());

        int curr_div = 0;
        while (!(rem < other))
        {
            rem = rem - other;
            curr_div++;
        }

        quo.bignum_vector.push_back(curr_div);
    }

    quo.remove_excess();
    return quo;
}

/// @brief Modulo operator for Bignum.
/// @param other The Bignum to compute the modulo with.
/// @return A new Bignum representing the remainder.
Bignum Bignum::operator%(const Bignum &other) const
{
    return *this - ((*this / other) * other);
}

/// @brief Modular exponentiation using the Bignum class.
/// @param base The base Bignum.
/// @param exponent The exponent Bignum.
/// @param modulus The modulus Bignum.
/// @return A new Bignum representing the modular exponentiation result.
Bignum Bignum::mod_exponent(const Bignum &base, const Bignum &exponent, const Bignum &modulus) const
{
    Bignum mod_exp("1");
    Bignum curr_base = base % modulus;
    Bignum curr_exponent = exponent;

    const Bignum zero("0");
    const Bignum two("2");

    std::vector<std::future<Bignum>> futures;
    std::mutex mod_exp_mutex;

    while (!(curr_exponent == zero))
    {
        std::vector<std::future<void>> mod_parallel;

        if (curr_exponent.bignum_vector.back() % 2 != 0)
        {
            mod_parallel.push_back(std::async(std::launch::async, [&]()
                                              {
                                                  Bignum curr_mod_exp = (mod_exp * curr_base) % modulus;
                                                  std::lock_guard<std::mutex> lock(mod_exp_mutex);
                                                  mod_exp = curr_mod_exp; }));
        }

        auto square_mod_future = std::async(std::launch::async, [&]()
                                            { return (curr_base * curr_base) % modulus; });

        for (auto &mod : mod_parallel)
            mod.wait();

        curr_base = square_mod_future.get();
        curr_exponent = curr_exponent / two;
    }

    mod_exp.remove_excess();
    return mod_exp;
}

/// @brief Converts the Bignum to a string representation.
/// @return A string representation of the Bignum.
std::string Bignum::to_string() const
{
    std::string result;
    for (const int curr_dig : bignum_vector)
    {
        result += std::to_string(curr_dig);
    }
    return result;
}

/// @brief Converts a string to a Bignum.
/// @param str The string to convert.
/// @return A Bignum representing the input string.
Bignum Bignum::string_to_bignum(const std::string &str) const
{
    std::string to_convert;

    for (const char ch : str)
    {
        std::ostringstream oss;
        oss << std::setw(3) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(ch));
        to_convert += oss.str();
    }

    return Bignum(to_convert);
}

/// @brief Converts a Bignum to a string.
/// @param bignum The Bignum to convert.
/// @return A string representation of the Bignum.
std::string Bignum::bignum_to_string(const Bignum &bignum) const
{
    std::string to_convert = bignum.to_string();

    std::string new_str;

    if (to_convert.length() % 3 != 0)
        to_convert.insert(0, 3 - (to_convert.length() % 3), '0');

    for (size_t i = 0; i < to_convert.length(); i += 3)
    {
        const std::string ascii = to_convert.substr(i, 3);
        new_str += static_cast<char>(std::stoi(ascii));
    }

    return new_str;
}

/// @brief Pads a string with spaces and a line number.
/// @param input The input string to pad.
/// @param line_num The line number to include in the padding.
/// @return A padded string.
std::string Bignum::padding(const std::string &input, int line_num) const
{
    std::ostringstream oss;
    oss << std::setw(3) << std::setfill(' ') << line_num;
    std::string result = oss.str() + input;

    const size_t padding_check = 102 - result.length();

    result.append(padding_check - 3, ' ');
    result.append(oss.str());

    return result;
}

/// @brief Encrypts a large text using RSA in chunks.
/// @param text The text to encrypt.
/// @return A vector of encrypted pairs of strings.
std::vector<std::pair<std::string, std::string>> Bignum::large_encrypt(const std::string &text) const
{
    std::vector<std::pair<std::string, std::string>> encrypted_lines;
    std::istringstream stream(text);
    std::string line;
    int line_num = 1;

    std::vector<std::future<std::pair<std::string, std::string>>> encrypt_parallel;

    while (std::getline(stream, line))
    {
        if (line.length() > MAX_CHARS_PER_CHUNK)
            line = line.substr(0, MAX_CHARS_PER_CHUNK);

        const std::string padded_line = padding(line, line_num);

        encrypt_parallel.push_back(std::async(std::launch::async, [this, padded_line]() -> std::pair<std::string, std::string>
                                              {
            const Bignum first_encrypted = mod_exponent(string_to_bignum(padded_line.substr(0, 51)), public_exp, public_mod);
            const Bignum second_encrypted = mod_exponent(string_to_bignum(padded_line.substr(51)), public_exp, public_mod);
            return {first_encrypted.to_string(), second_encrypted.to_string()}; }));

        line_num++;
    }

    for (auto &encryption : encrypt_parallel)
        encrypted_lines.push_back(encryption.get());

    return encrypted_lines;
}

/// @brief Decrypts a large text using RSA.
/// @param first The first part of the encrypted string.
/// @param second The second part of the encrypted string.
/// @return The decrypted string.
std::string Bignum::large_decrypt(const std::string &first, const std::string &second) const
{
    Bignum first_decrypted, second_decrypted;
    std::mutex result_mutex;

    std::thread first_thread([&]()
                             { first_decrypted = mod_exponent(Bignum(first), priv_exp, public_mod); });

    std::thread second_thread([&]()
                              { second_decrypted = mod_exponent(Bignum(second), priv_exp, public_mod); });

    first_thread.join();
    second_thread.join();

    std::string decrypted_str;

    std::thread decryption_thread([&]()
                                  {
        decrypted_str = bignum_to_string(first_decrypted) + bignum_to_string(second_decrypted);
        decrypted_str = decrypted_str.substr(3, decrypted_str.length() - 6);

        while (!decrypted_str.empty() && decrypted_str.back() == ' ')
        {
            decrypted_str.pop_back();
        } });

    decryption_thread.join();

    return decrypted_str;
}
