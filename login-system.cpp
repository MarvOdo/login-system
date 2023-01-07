#include <iostream>
#include <fstream>
#include <string>
#include "encryption.h"

using namespace std;

//session class used when an account is logged in
class Session
{
private:
    string name, age, fc;

public:
    //takes information of account from database to make it easily available to user
    Session(string n, string a, string f)
    {
        name = n;
        age = a;
        fc = f;

        //continuous actions for the user until "logout" command is given
        while (true)
        {
            cout << "What would you like to display?\n"
                << "\'name\', \'age\', or \'favorite color\'\n"
                << "\'logout\' to logout and go to main menu.\n";
            string action;
            getline(cin, action);
            if (action == "name")
            {
                cout << getName() << "\n\n";
            }
            else if (action == "age")
            {
                cout << getAge() << "\n\n";
            }
            else if (action == "favorite color")
            {
                cout << getFC() << "\n\n";
            }
            else if (action == "logout")
            {
                break;
            }
            else
            {
                cout << "ERROR: Invalid command.\n\n";
            }
        }
    }

    string getName()
    {
        return name;
    }

    string getAge()
    {
        return age;
    }

    string getFC()
    {
        return fc;
    }
};

//creates a database, can write to it to register users, and reads it to check credentials for login
class Database
{
private:
    string FileName;
    Encryption Encryptor;

public:
    //creation of database file (expected format is csv)
    Database(string fn)
    {
        FileName = fn;
        ofstream database(fn);
        database << "username,password,name,age,fav-color\n";
        database.close();
    }

    //take in information to register a user in database
    void Register()
    {
        string user[5];

        cout << "\nUsername: ";
        getline(cin, user[0]);
        cout << "\nPassword: ";
        getline(cin, user[1]);
        user[1] = Encryptor.SHA256(user[1]); //hash of password is stored, not plain password
        cout << "\nName: ";
        getline(cin, user[2]);
        cout << "\nAge: ";
        getline(cin, user[3]);
        cout << "\nFavorite Color: ";
        getline(cin, user[4]);

        fstream database;
        database.open(FileName, ios::app);
        database << user[0] << "," << user[1] << "," << user[2] << "," << user[3] << "," << user[4] << "\n";
        database.close();
    }

    //check in database file if inputted credentials match any in the database
    void Login()
    {
        string credentials[2];

        cout << "\nUsername: ";
        getline(cin, credentials[0]);
        cout << "\nPassword: ";
        getline(cin, credentials[1]);
        credentials[1] = Encryptor.SHA256(credentials[1]); //again, it's the hashes that are compared

        string un, pw, name, age, fc, rest;
        fstream database;
        database.open(FileName, ios::in);
        while (getline(database, un, ',')) {
            if (un == credentials[0])
            {
                getline(database, pw, ',');
                if (pw == credentials[1])
                {
                    cout << "Logged in successfully!\n\n";
                    getline(database, name, ',');
                    getline(database, age, ',');
                    getline(database, fc);
                    Session currentSession = Session(name, age, fc); //if successful login, session is started
                    cout << "Logged out!\n\n"; //once while loop ends inside currentSession constructor, session ends
                    return;
                }
                cout << "\nERROR: Wrong password!\n";
                return;
            }

            getline(database, rest);
        }
        cout << "\nERROR: Username doesn't exist!\n";
    }
};

int main()
{
    //create database file
    Database users = Database("users.csv");

    string action;
    
    //loop actions until "quit" command is given
    while (true)
    {
        cout << "Welcome! Please type in an action to perform.\n"
            << "\'register\', \'login\', or \'quit\'\n";
        getline(cin, action);

        if (action == "register")
        {
            users.Register();
        }
        else if (action == "login")
        {
            users.Login();
        }
        else if (action == "quit")
        {
            break;
        }
        else
        {
            cout << "ERROR: That is not a valid command.\n"
                << "Please type \'register\', \'login\', or \'quit\'\n";
            getline(cin, action);
        }
    }

    return 0;
}