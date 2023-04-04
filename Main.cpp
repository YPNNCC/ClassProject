#include <functional>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include "Main.h"

using namespace std;

const string fileName = "users.txt";
const string adminUsername = "admin";
const string adminPassword = "admin123";
const int adminPermissionLevel = 4;

int main() {
	doPrep();
    login();
    return 0;
}

void doPrep() {
    ifstream file;
    file.open(fileName);
    if (file.fail()) {
        ofstream file;
        file.open(fileName);

        string encryptedPassword = encrypt(adminPassword) + "," + to_string(adminPermissionLevel);
        file << adminUsername << "," << encryptedPassword << endl;
        file.close();
    } else if (file.peek() == ifstream::traits_type::eof()) {
        file.close();
        ofstream file;
        file.open(fileName);

        string encryptedPassword = encrypt(adminPassword) + "," + to_string(adminPermissionLevel);
        file << adminUsername << "," << encryptedPassword << endl;
        file.close();
    } else {
        file.close();
    }
}

void login() {
	bool loggedIn = false;
	string username, password;
	int permissionLevel;

	while (!loggedIn) {
		cout << "Enter username: ";
		getline(cin, username);
		cout << "Enter password: ";
		getline(cin, password);

		ifstream file;
		file.open(fileName);
		if (file.fail()) {
			cout << "Failed to open file.\n";
			return;
		}

		string savedUsername, savedPassword, permissionLevelStr;
		while (getline(file, savedUsername, ',')) {
			getline(file, savedPassword, ',');
			getline(file, permissionLevelStr);
			
			if (savedUsername == username) {
				string hashedPassword = encrypt(password);
				if (hashedPassword == savedPassword) {
					loggedIn = true;
					permissionLevel = stoi(permissionLevelStr);
					cout << "Successfully logged in as " << username << ". Permission level: " << permissionLevelStr << ".\n";
					break;
				}
			}
		}

		file.close();
		if (!loggedIn) cout << "Invalid username or password.\n";
	}

	int choice;
	while (loggedIn) {
		cout << "1. Add user (permission level 1)\n";
		cout << "2. Delete user (permission level 2)\n";
		cout << "3. View all users (permission level 3)\n";
		cout << "4. Reset user password (permission level 3)\n";
		cout << "5. Modify user permissions (permission level 4)\n";
		cout << "6. Exit\n";
		cout << "Enter choice: ";
		cin >> choice;

        if (cin.fail()) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "\n\nInvalid choice.\n\n";
            continue;
        }

		cin.ignore();

		switch (choice) {
			case 1:
				if (permissionLevel >= 1) {
					addUser(permissionLevel);
					break;
				}

				cout << "You do not have permission to add users.\n";
				break;
			case 2:
				if (permissionLevel >= 2) {
					deleteUser(username, permissionLevel);
					break;
				}
				
				cout << "You do not have permission to delete users.\n";
				break;
			case 3:
				if (permissionLevel >= 3) {
					printAllUsers();
					break;
				}

				cout << "You do not have permission to view all users.\n";
				break;
			case 4:
				if (permissionLevel >= 3) {
					resetPassword();
					break;
				}

				cout << "You do not have permission to reset user passwords.\n";
				break;
			case 5:
				if (permissionLevel >= 4) {
					modifyPermissions(username, permissionLevel);
					break;
				}

				cout << "You do not have permission to modify user permissions.\n";
				break;
			case 6:
				loggedIn = false;
				break;
			default:
				cout << "Invalid choice.\n";
				break;
		}

		cout << endl;
	}
}

void addUser(int executingPermission) {
    string username, password;
	int permissionLevel = 0;
	
	ofstream file;
    file.open(fileName, ios::app);
    if (file.fail()) {
        cout << "Failed to open file.\n";
        return;
    }
	
    cout << "Enter username: ";
    getline(cin, username);
    cout << "Enter password: ";
    getline(cin, password);

	sanitizeInput(username);
	sanitizeInput(password);

	if (password.length() < 8) {
		cout << "Password must be at least 8 characters long.\n";
		file.close();
		return;
	}
	
	if (executingPermission >= 3) {
		cout << "Enter permission level: ";
		cin >> permissionLevel;
		cin.ignore();

		if (permissionLevel < 1 || permissionLevel > 4) {
			cout << "Invalid permission level. Defaulting to 0.\n";
			permissionLevel = 0;
		}
	}
	
    string encryptedPassword = encrypt(password) + "," + to_string(permissionLevel);
	
    ifstream checkFile;
    checkFile.open(fileName);
    if (checkFile.fail()) {
        cout << "Failed to open file.\n";
        file.close();
        return;
    }
	
    string savedUsername, savedPassword;
    while (getline(checkFile, savedUsername, ',')) {
        getline(checkFile, savedPassword);
        if (savedUsername == username) {
            cout << "Username already exists.\n";
            checkFile.close();
            file.close();
            return;
        }
    }

    checkFile.close();
    file << username << "," << encryptedPassword << endl;
    cout << "User added successfully.\n";
    file.close();
}

void deleteUser(string executingUsername, int executingPermission) {
    string username;
    ifstream file;
    ofstream tempFile;
    file.open(fileName);
    if (file.fail()) {
        cout << "Failed to open file.\n";
        return;
    }

    tempFile.open("temp.txt");
    if (tempFile.fail()) {
        cout << "Failed to open file.\n";
        file.close();
        return;
    }
    
    cout << "Enter username to delete: ";
    getline(cin, username);
    
    if (!std::all_of(username.begin(), username.end(), isalnum)) {
        cout << "Invalid username.\n";
        return;
    }
    
    string savedUsername, savedPassword, permissionLevelStr;
    int permissionLevel;

    bool foundUser = false;
	while (getline(file, savedUsername, ','))
	{
		getline(file, savedPassword, ',');
		getline(file, permissionLevelStr);

		permissionLevel = stoi(permissionLevelStr);

		if (savedUsername != username) tempFile << savedUsername << "," << savedPassword << "," << permissionLevelStr << endl;
		else foundUser = true;
	}

    file.close();
    tempFile.close();
    if (!foundUser) {
        cout << "User not found.\n";
        remove("temp.txt");
        return;
    }

    if (username == executingUsername || executingPermission <= permissionLevel) {
        cout << "You do not have permission to delete this user.\n";
        remove("temp.txt");
        return;
    }

	if (permissionLevel < 0 || permissionLevel > 4) {
		cout << "Invalid permission level.\n";
		remove("temp.txt");
		return;
	}

    remove(fileName.c_str());
    rename("temp.txt", fileName.c_str());
    cout << "User deleted successfully.\n";
}

void printAllUsers() {
    ifstream file;
    file.open(fileName);
    
    string savedUsername, savedPassword;
    while (getline(file, savedUsername, ',')) {
        getline(file, savedPassword);
        cout << savedUsername << " " << savedPassword << endl;
    }

    file.close();
}

void modifyPermissions(string executingUsername, int executingPermission) {
    string username;
    int newPermissionLevel;

    cout << "Enter username: ";
    getline(cin, username);

    ifstream file;
    file.open(fileName);

    bool foundUser = false;
    string savedUsername, savedPassword;
    while (getline(file, savedUsername, ',')) {
        getline(file, savedPassword);
        if (savedUsername == username) {
            foundUser = true;
            break;
        }
    }

    file.close();

    if (!foundUser) {
        cout << "User not found.\n";
        return;
    }

    if (username == executingUsername) {
        cout << "You cannot modify your own permissions.\n";
        return;
    }

    cout << "Enter new permission level (0-4): ";
    cin >> newPermissionLevel;
    cin.ignore();

    if (newPermissionLevel < 0 || newPermissionLevel > 4) {
        cout << "Invalid permission level.\n";
        return;
    }

    if (executingPermission < 3) {
        cout << "You do not have permission to modify user permissions.\n";
        return;
    }

    if (executingPermission == 3 && newPermissionLevel >= 3) {
        cout << "You do not have permission to modify users with permission level 3 or 4.\n";
        return;
    }

    file.open(fileName);
    if (file.fail()) {
        cout << "Failed to open file.\n";
        return;
    }

    ofstream tempFile;
    tempFile.open("temp.txt");
    if (tempFile.fail()) {
        cout << "Failed to open file.\n";
        file.close();
        return;
    }

    while (getline(file, savedUsername, ',')) {
        getline(file, savedPassword);
        if (savedUsername != username) {
            tempFile << savedUsername << "," << savedPassword << endl;
        } else {
            string encryptedPassword = savedPassword.substr(0, savedPassword.find(",")) + "," + to_string(newPermissionLevel);
            tempFile << savedUsername << "," << encryptedPassword << endl;
        }
    }

    file.close();
    tempFile.close();

    remove(fileName.c_str());
    rename("temp.txt", fileName.c_str());

    cout << "Permission level updated successfully.\n";
}

void resetPassword() {
    string username;
    ifstream file;
    ofstream tempFile;
    file.open(fileName);
    if (file.fail()) {
        cout << "Failed to open file.\n";
        return;
    }

    tempFile.open("temp.txt");
    if (tempFile.fail()) {
        cout << "Failed to open file.\n";
        file.close();
        return;
    }

    cout << "Enter username to reset password: ";
    getline(cin, username);
    string savedUsername, savedPassword;
    bool foundUser = false;
    while (getline(file, savedUsername, ',')) {
        getline(file, savedPassword);
        if (savedUsername != username) {
            tempFile << savedUsername << "," << savedPassword << endl;
        } else {
            foundUser = true;
            string newPassword;
            cout << "Enter new password: ";
            getline(cin, newPassword);
            string encryptedPassword = encrypt(newPassword) + "," + savedPassword.substr(savedPassword.find(",") + 1);
            tempFile << savedUsername << "," << encryptedPassword << endl;
        }
    }

    file.close();
    tempFile.close();
    if (!foundUser) {
        cout << "User not found.\n";
        remove("temp.txt");
        return;
    }

    remove(fileName.c_str());
    rename("temp.txt", fileName.c_str());
    cout << "Password reset successfully.\n";
}

string sha256(string& str) {
	ostringstream os;
	hash<string> hash_fn;
	size_t hash = hash_fn(str);
	os << hex << setfill('0') << setw(16) << hash;
	return os.str();
}

string encrypt(string password) {
	string salt = "DVgDdXy2k2gUxMGJx7j7BKS2"; // just some random salt
	string passwordAndSalt = password + salt;
	return sha256(passwordAndSalt);
}

bool verifyPassword(string password, string hashedPassword) {
	string salt = "DVgDdXy2k2gUxMGJx7j7BKS2"; // just some random salt
	string passwordAndSalt = password + salt;
	return sha256(passwordAndSalt) == hashedPassword;
}

void sanitizeInput(string& input) {
	string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	input.erase(remove_if(input.begin(), input.end(), [&validChars](char c)
	{
		return validChars.find(c) == string::npos;
	}), input.end());
}