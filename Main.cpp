#include <functional>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include "Main.h"

const std::string file_name = "users.txt";
const std::string admin_username = "admin";
const std::string admin_password = "admin123";
constexpr int admin_permission_level = 4;

int main() {
	do_prep();
    login();
    return 0;
}

void do_prep() {
    std::fstream file;
    file.open(file_name);
    if (file.fail()) {
        std::string encrypted_password = encrypt(admin_password) + "," + std::to_string(admin_permission_level);
        file << admin_username << "," << encrypted_password << std::endl;
        file.close();
    } else if (file.peek() == std::ifstream::traits_type::eof()) {
        file.close();
        std::ofstream file;
        file.open(file_name);

        std::string encrypted_password = encrypt(admin_password) + "," + std::to_string(admin_permission_level);
        file << admin_username << "," << encrypted_password << std::endl;
        file.close();
    } else {
        file.close();
    }
}

void login() {
	bool logged_in = false;
	std::string username, password;
	int permission_level = 0;

	while (!logged_in) {
		std::cout << "Enter username: ";
		getline(std::cin, username);
		std::cout << "Enter password: ";
		getline(std::cin, password);

		std::ifstream file;
		file.open(file_name);
		if (file.fail()) {
			std::cout << "Failed to open file.\n";
			return;
		}

		std::string saved_username, saved_password, permission_level_str;
		while (getline(file, saved_username, ',')) {
			getline(file, saved_password, ',');
			getline(file, permission_level_str);
			
			if (saved_username == username) {
				std::string hashed_password = encrypt(password);
				if (hashed_password == saved_password) {
					logged_in = true;
					permission_level = stoi(permission_level_str);
					std::cout << "Successfully logged in as " << username << ". Permission level: " << permission_level_str << ".\n";
					break;
				}
			}
		}

		file.close();
		if (!logged_in) std::cout << "Invalid username or password.\n";
	}

	int choice;
	while (logged_in) {
		std::cout << "1. Add user (permission level 1)\n";
		std::cout << "2. Delete user (permission level 2)\n";
		std::cout << "3. View all users (permission level 3)\n";
		std::cout << "4. Reset user password (permission level 3)\n";
		std::cout << "5. Modify user permissions (permission level 4)\n";
		std::cout << "6. Exit\n";
		std::cout << "Enter choice: ";
		std::cin >> choice;

        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "\n\nInvalid choice.\n\n";
            continue;
        }

		std::cin.ignore();

		switch (choice) {
			case 1:
				if (permission_level >= 1) {
					add_user(permission_level);
					break;
				}

				std::cout << "You do not have permission to add users.\n";
				break;
			case 2:
				if (permission_level >= 2) {
					delete_user(username, permission_level);
					break;
				}
				
				std::cout << "You do not have permission to delete users.\n";
				break;
			case 3:
				if (permission_level >= 3) {
					print_all_users();
					break;
				}

				std::cout << "You do not have permission to view all users.\n";
				break;
			case 4:
				if (permission_level >= 3) {
					reset_password();
					break;
				}

				std::cout << "You do not have permission to reset user passwords.\n";
				break;
			case 5:
				if (permission_level >= 4) {
					modify_permissions(username, permission_level);
					break;
				}

				std::cout << "You do not have permission to modify user permissions.\n";
				break;
			case 6:
				logged_in = false;
				break;
			default:
				std::cout << "Invalid choice.\n";
				break;
		}

		std::cout << std::endl;
	}
}

void add_user(int executing_permission) {
    std::string username, password;
	int permission_level = 0;
	
	std::ofstream file;
    file.open(file_name, std::ios::app);
    if (file.fail()) {
        std::cout << "Failed to open file.\n";
        return;
    }
	
    std::cout << "Enter username: ";
    getline(std::cin, username);
    std::cout << "Enter password: ";
    getline(std::cin, password);

	sanitize_input(username);
	sanitize_input(password);

	if (!is_strong_password(password)) {
		std::cout << "Password is not strong enough! Must be at least 8 characters long, have at least one uppercase and lowercase letter, and have at least one digit.\n";
		file.close();
		return;
	}
	
	if (executing_permission >= 3) {
		std::cout << "Enter permission level: ";
		std::cin >> permission_level;
		std::cin.ignore();

		if (permission_level < 1 || permission_level > 4) {
			std::cout << "Invalid permission level. Defaulting to 0.\n";
			permission_level = 0;
		}
	}
	
    std::string encrypted_password = encrypt(password) + "," + std::to_string(permission_level);
	
    std::ifstream check_file;
    check_file.open(file_name);
    if (check_file.fail()) {
        std::cout << "Failed to open file.\n";
        file.close();
        return;
    }
	
    std::string saved_username, saved_password;
    while (getline(check_file, saved_username, ',')) {
        getline(check_file, saved_password);
        if (saved_username == username) {
            std::cout << "Username already exists.\n";
            check_file.close();
            file.close();
            return;
        }
    }

    check_file.close();
    file << username << "," << encrypted_password << std::endl;
    std::cout << "User added successfully.\n";
    file.close();
}

void delete_user(const std::string& executing_username, int executing_permission) {
    std::string username;
    std::ifstream file;
    std::ofstream temp_file;
    file.open(file_name);
    if (file.fail()) {
        std::cout << "Failed to open file.\n";
        return;
    }

    temp_file.open("temp.txt");
    if (temp_file.fail()) {
        std::cout << "Failed to open file.\n";
        file.close();
        return;
    }
    
    std::cout << "Enter username to delete: ";
    getline(std::cin, username);
    
    if (!std::all_of(username.begin(), username.end(), isalnum)) {
        std::cout << "Invalid username.\n";
        return;
    }
    
    std::string saved_username, saved_password, permission_level_str;
    int permission_level = 0;

    bool found_user = false;
	while (getline(file, saved_username, ','))
	{
		getline(file, saved_password, ',');
		getline(file, permission_level_str);

		permission_level = stoi(permission_level_str);

		if (saved_username != username) temp_file << saved_username << "," << saved_password << "," << permission_level_str << std::endl;
		else found_user = true;
	}

    file.close();
    temp_file.close();
    if (!found_user) {
        std::cout << "User not found.\n";
        remove("temp.txt");
        return;
    }

    if (username == executing_username || executing_permission <= permission_level) {
        std::cout << "You do not have permission to delete this user.\n";
        remove("temp.txt");
        return;
    }

	if (permission_level < 0 || permission_level > 4) {
		std::cout << "Invalid permission level.\n";
		std::remove("temp.txt");
		return;
	}

    remove(file_name.c_str());
    rename("temp.txt", file_name.c_str());
    std::cout << "User deleted successfully.\n";
}

void print_all_users() {
    std::ifstream file;
    file.open(file_name);
    
    std::string saved_username, saved_password;
    while (getline(file, saved_username, ',')) {
        getline(file, saved_password);
        std::cout << saved_username << " " << saved_password << std::endl;
    }

    file.close();
}

void modify_permissions(const std::string& executing_username, int executing_permission) {
    std::string username;
    int new_permission_level;

    std::cout << "Enter username: ";
    getline(std::cin, username);

    std::ifstream file;
    file.open(file_name);

    bool found_user = false;
    std::string saved_username, saved_password;
    while (getline(file, saved_username, ',')) {
        getline(file, saved_password);
        if (saved_username == username) {
            found_user = true;
            break;
        }
    }

    file.close();

    if (!found_user) {
        std::cout << "User not found.\n";
        return;
    }

    if (username == executing_username) {
        std::cout << "You cannot modify your own permissions.\n";
        return;
    }

    std::cout << "Enter new permission level (0-4): ";
    std::cin >> new_permission_level;
    std::cin.ignore();

    if (new_permission_level < 0 || new_permission_level > 4) {
        std::cout << "Invalid permission level.\n";
        return;
    }

    if (executing_permission < 3) {
        std::cout << "You do not have permission to modify user permissions.\n";
        return;
    }

    if (executing_permission == 3 && new_permission_level >= 3) {
        std::cout << "You do not have permission to modify users with permission level 3 or 4.\n";
        return;
    }

    file.open(file_name);
    if (file.fail()) {
        std::cout << "Failed to open file.\n";
        return;
    }

    std::ofstream temp_file;
    temp_file.open("temp.txt");
    if (temp_file.fail()) {
        std::cout << "Failed to open file.\n";
        file.close();
        return;
    }

    while (getline(file, saved_username, ',')) {
        getline(file, saved_password);
        if (saved_username != username) {
            temp_file << saved_username << "," << saved_password << std::endl;
        } else {
            std::string encrypted_password = saved_password.substr(0, saved_password.find(",")) + "," + std::to_string(new_permission_level);
            temp_file << saved_username << "," << encrypted_password << std::endl;
        }
    }

    file.close();
    temp_file.close();

    remove(file_name.c_str());
    rename("temp.txt", file_name.c_str());

    std::cout << "Permission level updated successfully.\n";
}

void reset_password() {
    std::string username;
    std::ifstream file;
    std::ofstream temp_file;
    file.open(file_name);
    if (file.fail()) {
        std::cout << "Failed to open file.\n";
        return;
    }

    temp_file.open("temp.txt");
    if (temp_file.fail()) {
        std::cout << "Failed to open file.\n";
        file.close();
        return;
    }

    std::cout << "Enter username to reset password: ";
    getline(std::cin, username);
    std::string saved_username, saved_password;
    bool found_user = false;
    while (getline(file, saved_username, ',')) {
        getline(file, saved_password);
        if (saved_username != username) {
            temp_file << saved_username << "," << saved_password << std::endl;
        } else {
            found_user = true;
            std::string new_password;
            std::cout << "Enter new password: ";
            getline(std::cin, new_password);
            std::string encrypted_password = encrypt(new_password) + "," + saved_password.substr(saved_password.find(",") + 1);
            temp_file << saved_username << "," << encrypted_password << std::endl;
        }
    }

    file.close();
    temp_file.close();
    if (!found_user) {
        std::cout << "User not found.\n";
        remove("temp.txt");
        return;
    }

    remove(file_name.c_str());
    rename("temp.txt", file_name.c_str());
    std::cout << "Password reset successfully.\n";
}

std::string sha256(const std::string& str) {
	std::ostringstream os;
	constexpr std::hash<std::string> hash_fn;
	const size_t hash = hash_fn(str);
	os << std::hex << std::setfill('0') << std::setw(16) << hash;
	return os.str();
}

std::string encrypt(const std::string& password) {
	const std::string salt = "DVgDdXy2k2gUxMGJx7j7BKS2"; // just some random salt
	std::string password_and_salt = password + salt;
	return sha256(password_and_salt);
}

bool verify_password(const std::string& password, const std::string& hashed_password) {
	const std::string salt = "DVgDdXy2k2gUxMGJx7j7BKS2"; // just some random salt
	std::string password_and_salt = password + salt;
	return sha256(password_and_salt) == hashed_password;
}

void sanitize_input(std::string& input) {
	std::string valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	input.erase(remove_if(input.begin(), input.end(), [&valid_chars](const char c)
	{
		return valid_chars.find(c) == std::string::npos;
	}), input.end());
}

bool is_strong_password(const std::string& password) {
	bool has_upper_case = false, has_lower_case = false, has_digit = false;
	
	for (const char c : password) {
		if (isupper(c)) has_upper_case = true;
		if (islower(c)) has_lower_case = true;
		if (isdigit(c)) has_digit = true;
	}
	
	return password.length() >= 8 && has_upper_case && has_lower_case && has_digit;
}