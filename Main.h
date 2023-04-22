#ifndef MAIN_H
#define MAIN_H

#include <string>

void do_prep();
void login();
void add_user(int);
void delete_user(const std::string&, int);
void print_all_users();
void modify_permissions(const std::string&, int);
void reset_password();
std::string sha256(const std::string&);
std::string encrypt(const std::string&);
bool verify_password(const std::string&, const std::string&);
void sanitize_input(std::string&);
bool is_strong_password(const std::string&);

#endif // !Main

