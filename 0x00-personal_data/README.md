# 0x00. Personal data 

This directory contains a project focused on handling and securing personal data. It includes tasks such as filtering PII from logs, encrypting passwords, and securely accessing databases.

## Learning Objectives

By the end of this project, you will be able to:

- Identify examples of Personally Identifiable Information (PII)
- Implement a log filter to obfuscate PII fields
- Encrypt and validate passwords
- Authenticate to a database using environment variables

## Tasks

### Task 0: Regex-ing

Implement `filter_datum` to obfuscate PII fields in a log message using regex.

### Task 1: Log formatter

Create a `RedactingFormatter` class to format logs, filtering PII fields.

### Task 2: Create logger

Implement `get_logger` to create a logger with `RedactingFormatter`.

### Task 3: Connect to secure database

Implement `get_db` to securely connect to a database using environment variables.

### Task 4: Read and filter data

Implement a `main` function to read user data from a database and log it with PII fields filtered.

### Task 5: Encrypting passwords

Implement `hash_password` to hash and salt passwords using bcrypt.

### Task 6: Check valid password

Implement `is_valid` to check if a provided password matches a hashed password.

## Files

- `filtered_logger.py`: Contains the implementation for logging and database connection tasks.
- `encrypt_password.py`: Contains the implementation for password hashing and validation.
- `user_data.csv`: Sample data file used for testing.

## Setup

To run the code in this project, make sure you have the necessary dependencies installed:

```sh
pip install bcrypt mysql-connector-python

Usage

You can run the scripts directly from the command line. For example, to test the logging functionality:

sh

./main.py

Ensure that you have set the required environment variables for database connections.
