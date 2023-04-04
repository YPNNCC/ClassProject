#ifndef Main_H
#define Main_H

#include <string>

using namespace std;

void doPrep();
void login();
void addUser(int);
void deleteUser(string, int);
void printAllUsers();
void modifyPermissions(string, int);
void resetPassword();
string sha256(string&);
string encrypt(string);
bool verifyPassword(string, string);
void sanitizeInput(string&);
bool isStrongPassword(string);

#endif // !Main

