#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <openssl/sha.h>


std::string sha1_hex(const std::string& input) {
    unsigned char raw[SHA_DIGEST_LENGTH];
    SHA1(
        reinterpret_cast<const unsigned char*>(input.c_str()),
        input.size(),
        raw
    );

    char hex[SHA_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        std::sprintf(hex + i * 2, "%02x", static_cast<unsigned int>(raw[i]));
    }
    hex[SHA_DIGEST_LENGTH * 2] = '\0';

    return std::string(hex);
}


int main(int argc, char* argv[]) {

    if (argc < 3) {
        std::cerr << "Usage: mairon_dict_attack <sha1_hash> <wordlist_path>" << std::endl;
        std::cerr << "  sha1_hash     : lowercase hex SHA-1 of the target password" << std::endl;
        std::cerr << "  wordlist_path : full path to the wordlist file" << std::endl;
        return 1;
    }

    std::string target_hash  = argv[1];
    std::string wordlist_path = argv[2];


    for (char& c : target_hash) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    // Open the wordlist file
    std::ifstream wordlist(wordlist_path, std::ios::in);
    if (!wordlist.is_open()) {
        std::cerr << "ERROR: Cannot open wordlist at: " << wordlist_path << std::endl;
        return 1;
    }

    std::string      word;
    long long        words_checked = 0;

    auto start = std::chrono::high_resolution_clock::now();

    while (std::getline(wordlist, word)) {
        if (!word.empty() && word.back() == '\r') {
            word.pop_back();
        }
        words_checked++;
        if (sha1_hex(word) == target_hash) {
            auto end     = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(end - start).count();
            std::cout << "FOUND"          << std::endl;
            std::cout << words_checked    << std::endl;
            std::cout << elapsed          << std::endl;
            return 0;
        }
    }
    auto end     = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(end - start).count();

    std::cout << "NOT_FOUND"     << std::endl;
    std::cout << words_checked   << std::endl;
    std::cout << elapsed         << std::endl;
    return 0;
}
