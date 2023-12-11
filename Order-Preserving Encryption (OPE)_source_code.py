#!/usr/bin/env python
# coding: utf-8

# In[1]:


import os
import pymysql
import bcrypt
from getpass import getpass
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from prettytable import PrettyTable
from faker import Faker
import random

# AES Encryption setup
def generate_aes_key():
    return os.urandom(32)  # AES key size 

def encrypt_data_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + ' ' * (16 - len(data) % 16)
    encrypted_data = encryptor.update(padded_data.encode()) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def decrypt_data_aes(data, key):
    try:
        data = base64.b64decode(data)
        iv = data[:16]
        encrypted_data = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted_data.rstrip().decode()
    except Exception as e:
        print(f"Decryption failed with error: {e}")
        return None

# Order-Preserving Encryption (OPE) setup 
OPE_KEY = 10  # Example key for OPE

def simple_ope_encrypt(value):
    return value * OPE_KEY

def simple_ope_decrypt(value):
    return value / OPE_KEY

def get_user_role(cursor, username):
    try:
        cursor.execute("""
            SELECT role FROM user_credentials 
            WHERE username = %s
        """, (username,))
        user_record = cursor.fetchone()
        if user_record:
            return user_record['role']
    except Exception as e:
        print(f"Error getting user role: {e}")
        return None
    
# Generate record hash for integrity check
def generate_record_hash(patient_data):
    record_str = ''.join(str(patient_data[field]) for field in sorted(patient_data))
    return hashlib.sha256(record_str.encode()).hexdigest()

# Validate patient data
def validate_patient_data(patient_data):
    if patient_data['age'] < 0 or patient_data['weight'] < 0.0:
        raise ValueError("Age and weight should not be negative.")
    if not patient_data['first_name'] or not patient_data['last_name']:
        raise ValueError("First name and last name are required.")

# Populate patient data
def populate_patient_data(connection, cursor, num_records=100):
    fake = Faker()
    for _ in range(num_records):
        patient_data = {
            'first_name': fake.first_name(),
            'last_name': fake.last_name(),
            'gender': random.choice([True, False]),  # True for Male, False for Female
            'age': random.randint(0, 100),
            'weight': round(random.uniform(50.0, 100.0), 2),
            'height': round(random.uniform(150.0, 200.0), 2),
            'health_history': fake.text(),
            'record_hash': ''  # Placeholder for record hash
        }
        patient_data['record_hash'] = generate_record_hash(patient_data)
        insert_patient_data(connection, cursor, patient_data, 'admin')

# Create user and patient tables
# Create user table
def create_user_table(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_credentials (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARBINARY(256) NOT NULL,
            role ENUM('admin', 'user') NOT NULL
        );
    """)

# Create patient table
def create_patient_table(cursor):
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patient_info (
            id INT AUTO_INCREMENT PRIMARY KEY,
            first_name VARCHAR(100),
            last_name VARCHAR(100),
            encrypted_gender VARBINARY(256),
            encrypted_age VARBINARY(256),
            weight FLOAT,
            height FLOAT,
            health_history TEXT,
            record_hash VARBINARY(256) NOT NULL,
            key_gender VARBINARY(256),
            key_age VARBINARY(256)
        );
    """)

# Register new user
def register_user(connection, cursor, username, password, role):
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute("""
            INSERT INTO user_credentials (username, password_hash, role) 
            VALUES (%s, %s, %s)
        """, (username, password_hash, role))
        connection.commit()
    except pymysql.err.IntegrityError:
        print("Username already exists.")

# Authenticate user
def authenticate_user(cursor, username, password):
    cursor.execute("""
        SELECT password_hash FROM user_credentials 
        WHERE username = %s
    """, (username,))
    user_record = cursor.fetchone()
    if user_record and bcrypt.checkpw(password.encode('utf-8'), user_record['password_hash']):
        return True
    else:
        return False
    
# Function to verify data integrity
def verify_data_integrity(patient_data, stored_hash):
    calculated_hash = generate_record_hash(patient_data)
    return calculated_hash == stored_hash

# Function to generate checksum for a set of records
def generate_checksum(records):
    checksum = 0
    for record in records:
        checksum ^= int(hashlib.sha256(str(record).encode()).hexdigest(), 16)
    return checksum

# Function to add randomized padding for sensitive data
def pad_sensitive_data(data):
    padding_length = random.randint(1, 10)  # Random padding length
    return data + ('*' * padding_length)

def insert_patient_data(connection, cursor, patient_data, user_role):
    try:
        if user_role != 'admin':  
            raise PermissionError("Permission denied.")
        validate_patient_data(patient_data)
        
        gender_str = pad_sensitive_data(str(int(patient_data['gender'])))  # Padding gender data
        age_str = pad_sensitive_data(str(patient_data['age']))  # Padding age data

        key_gender = generate_aes_key()
        key_age = generate_aes_key()

        encrypted_gender = encrypt_data_aes(gender_str, key_gender)
        encrypted_age = encrypt_data_aes(age_str, key_age)

        # Encrypt weight using OPE
        encrypted_weight = simple_ope_encrypt(patient_data['weight'])

        cursor.execute("""
            INSERT INTO patient_info (
                first_name, last_name, encrypted_gender, encrypted_age, weight, height, health_history, record_hash, key_gender, key_age
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            patient_data['first_name'],
            patient_data['last_name'],
            encrypted_gender,
            encrypted_age,
            encrypted_weight,
            patient_data['height'],
            patient_data['health_history'],
            patient_data['record_hash'],
            base64.b64encode(key_gender).decode('utf-8'),
            base64.b64encode(key_age).decode('utf-8')
        ))
        connection.commit()
        print("Data inserted successfully.")
    except Exception as e:
        print(f"Error inserting data: {e}")
        
# Designed to interactively collect patient information from the admin
def add_patient_data(connection, cursor):
    print("Adding new patient data.")

    try:
        patient_data = {
            'first_name': input("Enter patient's first name: "),
            'last_name': input("Enter patient's last name: "),
            'gender': bool(input("Enter patient's gender (True for male, False for female): ")),
            'age': int(input("Enter patient's age: ")),
            'weight': float(input("Enter patient's weight: ")),
            'height': float(input("Enter patient's height: ")),
            'health_history': input("Enter patient's health history: "),
            'record_hash': ''  # Placeholder for record hash
        }

        validate_patient_data(patient_data)
        patient_data['record_hash'] = generate_record_hash(patient_data)
        insert_patient_data(connection, cursor, patient_data, 'admin')
    except ValueError as e:
        print(f"Error: {e}")

def retrieve_patient_data(cursor, user_role, weight_range=None):
    query = "SELECT id, first_name, last_name, encrypted_gender, encrypted_age, key_gender, key_age, weight, height, health_history, record_hash FROM patient_info"

    if weight_range:
        # Convert the range into encrypted range
        encrypted_range = (simple_ope_encrypt(weight_range[0]), simple_ope_encrypt(weight_range[1]))
        query += f" WHERE weight BETWEEN {encrypted_range[0]} AND {encrypted_range[1]}"

    cursor.execute(query)
    rows = cursor.fetchall()

    checksum = generate_checksum(rows)  # Calculate checksum for fetched records
    print("Checksum of retrieved records:", checksum)

    if user_role == 'admin':
        table = PrettyTable(["ID", "First Name", "Last Name", "Gender", "Age", "Weight", "Height", "Health History"])
    else:
        table = PrettyTable(["ID", "Gender", "Age", "Weight", "Height", "Health History"])

    for row in rows:
        # Decrypt gender and age
        key_gender = base64.b64decode(row['key_gender']) if row['key_gender'] else None
        key_age = base64.b64decode(row['key_age']) if row['key_age'] else None

        decrypted_gender = decrypt_data_aes(row['encrypted_gender'], key_gender) if row['encrypted_gender'] and key_gender else "Unknown"
        decrypted_age = decrypt_data_aes(row['encrypted_age'], key_age) if row['encrypted_age'] and key_age else "Unknown"

        # Decrypt weight using OPE
        decrypted_weight = simple_ope_decrypt(row['weight'])

        if user_role == 'admin':
            table.add_row([
                row.get("id"),
                row.get("first_name"),
                row.get("last_name"),
                decrypted_gender,
                decrypted_age,
                decrypted_weight,
                row.get("height"),
                row.get("health_history")
            ])
        else:
            table.add_row([
                row.get("id"),
                decrypted_gender,
                decrypted_age,
                decrypted_weight,
                row.get("height"),
                row.get("health_history")
            ])

    print(table)


# In[2]:


#General Test for functionality
def main():
    mysql_password = getpass('Enter MySQL password: ')
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password=mysql_password,
        charset='utf8mb4'
    )

    cursor = conn.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS healthdetailsdb")
    conn.commit()

    conn.close()

    # Now connect to the newly created database
    connection = pymysql.connect(
        host='localhost',
        user='root',
        password=mysql_password,
        database='healthdetailsdb',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

    authenticated_user = None
    user_role = None

    while True:
        if not authenticated_user:
            print("1. Login")
            print("2. Register")
            print("3. Test User Authentication (Admin Only)")
            print("4. Test Access Control (Admin Only)")
            print("5. Exit")
            choice = input("Enter choice: ")

            if choice == '1':
                username = input("Enter username: ")
                password = getpass("Enter password: ")
                if authenticate_user(connection.cursor(), username, password):
                    print("Login successful.")
                    authenticated_user = username
                    user_role = get_user_role(connection.cursor(), username)  # Get the user's role
                else:
                    print("Login failed.")
            elif choice == '2':
                username = input("Enter new username: ")
                password = getpass("Enter new password: ")
                role = input("Enter role (admin/user): ").lower()
                register_user(connection, connection.cursor(), username, password, role)
            elif choice == '3':
                if authenticated_user and user_role == 'admin':
                    test_user_authentication(connection)
                else:
                    print("Admin access required.")

            elif choice == '4':
                if authenticated_user and user_role == 'admin':
                    test_access_control(connection)
                else:
                    print("Admin access required.")

            elif choice == '5':
                break

        else:
            print("\nLogged in as:", authenticated_user)
            print("4. View Patient Data")
            if user_role == 'admin':
                print("5. Add Patient Data")
            print("6. Logout")
            choice = input("Enter choice: ")

            if choice == '4':
                retrieve_patient_data(connection.cursor(), user_role)
            elif choice == '5' and user_role == 'admin':
                add_patient_data(connection, connection.cursor())
            elif choice == '6':
                authenticated_user = None
                user_role = None

    connection.close()

if __name__ == "__main__":
    main()


# In[3]:


#OVERALL SCENARIO TESTING FOR FINAL REPORT and as per REQUIREMENTS
def establish_connection():
    mysql_password = getpass('Enter MySQL password for testing: ')
    connection = pymysql.connect(
        host='localhost',
        user='root',
        password=mysql_password,
        database='healthdetailsdb',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
    return connection

def test_ope_functionality(connection):
    print("Testing OPE Functionality...")
    test_weight = 75.0  # Example weight
    encrypted_weight = simple_ope_encrypt(test_weight)
    decrypted_weight = simple_ope_decrypt(encrypted_weight)
    assert decrypted_weight == test_weight, "OPE decryption did not return the original value"
    print("OPE Functionality test passed.")
    
def test_ope_range_query(connection):
    print("Testing OPE Range Query...")
    cursor = connection.cursor()

    # Define the weight range for the query
    weight_range_min = 70.0
    weight_range_max = 80.0

    # Encrypt the range limits
    encrypted_min = simple_ope_encrypt(weight_range_min)
    encrypted_max = simple_ope_encrypt(weight_range_max)

    # Perform the range query
    cursor.execute("""
        SELECT * FROM patient_info
        WHERE weight BETWEEN %s AND %s
    """, (encrypted_min, encrypted_max))

    # Fetch and decrypt the results
    records = cursor.fetchall()
    for record in records:
        decrypted_weight = simple_ope_decrypt(record['weight'])
        assert weight_range_min <= decrypted_weight <= weight_range_max, "Record out of range"

    print("OPE Range Query test passed.")

def test_data_integrity(connection):
    print("Testing Data Integrity...")
    cursor = connection.cursor()
    test_data = {
        'first_name': 'Test',
        'last_name': 'User',
        'gender': True,  # Assuming True for Male, False for Female
        'age': 30,
        'weight': 70.0,
        'height': 175.0,
        'health_history': 'Test history',
        'record_hash': ''  # Placeholder for record hash
    }
    insert_patient_data(connection, cursor, test_data, 'admin')
    cursor.execute("SELECT * FROM patient_info WHERE first_name = 'Test' AND last_name = 'User'")
    row = cursor.fetchone()
    assert row is not None, "Data insertion failed"
    # Tamper with the data
    cursor.execute("UPDATE patient_info SET weight = 80.0 WHERE first_name = 'Test' AND last_name = 'User'")
    connection.commit()
    # Try retrieving data
    cursor.execute("SELECT * FROM patient_info WHERE first_name = 'Test' AND last_name = 'User'")
    tampered_row = cursor.fetchone()
    assert tampered_row['weight'] != test_data['weight'], "Data integrity test failed: Tampered data not detected"
    print("Data Integrity test passed.")

def test_role_based_access_control(connection):
    print("Testing Role-Based Access Control...")
    cursor = connection.cursor()
    # Assuming 'admin' role has access to all fields and 'user' role has restricted access
    admin_role = 'admin'
    user_role = 'user'
    
    cursor.execute("SELECT COUNT(*) FROM patient_info")
    total_records = cursor.fetchone()['COUNT(*)']

    cursor.execute("SELECT COUNT(*) FROM patient_info WHERE key_gender IS NOT NULL AND key_age IS NOT NULL")
    accessible_records_admin = cursor.fetchone()['COUNT(*)']

    cursor.execute("SELECT COUNT(*) FROM patient_info WHERE key_gender IS NULL AND key_age IS NULL")
    accessible_records_user = cursor.fetchone()['COUNT(*)']

    assert accessible_records_admin == total_records, "Admin should access all records"
    assert accessible_records_user < total_records, "User should have restricted access"
    print("Role-Based Access Control test passed.")

def test_user_authentication(connection):
    print("Testing User Authentication...")
    cursor = connection.cursor()
    test_username = "test_user"
    test_password = "test_password"

    # Create a test user
    password_hash = bcrypt.hashpw(test_password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute("""
        INSERT INTO user_credentials (username, password_hash, role) 
        VALUES (%s, %s, 'user') ON DUPLICATE KEY UPDATE password_hash = %s
    """, (test_username, password_hash, password_hash))
    connection.commit()

    # Attempt to authenticate
    cursor.execute("""
        SELECT password_hash FROM user_credentials 
        WHERE username = %s
    """, (test_username,))
    user_record = cursor.fetchone()
    assert user_record and bcrypt.checkpw(test_password.encode('utf-8'), user_record['password_hash']), "Authentication failed"
    print("User Authentication test passed.")

def test_aes_encryption_for_other_attributes(connection):
    print("Testing AES Encryption for Other Attributes...")
    cursor = connection.cursor()

    # Test encryption of a sample data
    test_data = "test_data"
    
    # Generate a valid AES key
    valid_aes_key = generate_aes_key()

    encrypted_data = encrypt_data_aes(test_data, valid_aes_key)
    decrypted_data = decrypt_data_aes(encrypted_data, valid_aes_key)
    assert decrypted_data == test_data, "AES encryption/decryption failed"
    print("AES Encryption test passed.")
    
def test_general_functionality(connection):
    print("Testing General Functionality...")
    cursor = connection.cursor()

    # Clearing previous test data (if needed)
    cursor.execute("DELETE FROM patient_info WHERE first_name = 'Test' AND last_name LIKE 'Patient%'")
    connection.commit()

    # Test adding new patients with varied weights
    for i, weight in enumerate([65.0, 75.0, 85.0]):
        patient_data = {
            'first_name': 'Test',
            'last_name': f'Patient{i}',
            'gender': True,
            'age': 30,
            'weight': weight,
            'height': 170.0,
            'health_history': 'Test history',
            'record_hash': ''  # Placeholder for record hash
        }
        insert_patient_data(connection, cursor, patient_data, 'admin')

    # Retrieve and check weights
    cursor.execute("SELECT weight FROM patient_info WHERE first_name = 'Test' AND last_name LIKE 'Patient%'")
    retrieved_weights = [row['weight'] for row in cursor.fetchall()]
    assert len(retrieved_weights) == 3, f"Expected 3 records, got {len(retrieved_weights)}"

    # Check if the order of weights is preserved
    for i in range(len(retrieved_weights) - 1):
        assert retrieved_weights[i] < retrieved_weights[i + 1], "Retrieved weights are not in the correct order"

    print("General Functionality test passed.")
    
def main():
    connection = establish_connection()
    
    test_ope_functionality(connection)
    test_ope_range_query(connection)
    test_data_integrity(connection)
    test_role_based_access_control(connection)
    test_user_authentication(connection)
    test_aes_encryption_for_other_attributes(connection)
    test_general_functionality(connection)

    connection.close()

if __name__ == "__main__":
    main()


# In[4]:


import diagrams.generic.compute as compute
print(dir(compute))


# In[5]:


from diagrams import Diagram, Cluster
from diagrams.generic.database import SQL
from diagrams.generic.compute import Rack
from diagrams.generic.network import Firewall
from diagrams.generic.place import Datacenter
from diagrams.onprem.client import User

with Diagram("Secure DBaaS System Architecture", show="png", direction="LR"):

    with Cluster("User Interface Layer"):
        interface = User("User Interaction")

    with Cluster("Application Layer"):
        with Cluster("Authentication Module"):
            auth = Rack("Auth Module")
        with Cluster("Data Processing Unit"):
            data_proc = Rack("Data Proc Unit")
            encryption = Rack("AES Encryption")
            decryption = Rack("AES Decryption")
            ope = Rack("OPE")

    with Cluster("Database Layer"):
        with Cluster("User Credentials Table"):
            user_db = SQL("User DB")
        with Cluster("Patient Info Table"):
            patient_db = SQL("Patient DB")

    with Cluster("Admin Functions"):
        admin_funcs = Datacenter("Admin Ops")

    network = Firewall("Network Comm")

    interface >> auth >> data_proc
    data_proc >> [encryption, decryption, ope]
    encryption >> user_db
    decryption >> patient_db
    ope >> patient_db
    admin_funcs >> data_proc
    [user_db, patient_db] >> network


# In[ ]:




