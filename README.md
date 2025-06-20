# Secure DBaaS Project

## Overview

Secure DBaaS is a secure database-as-a-service simulation project designed to protect healthcare data using encryption and access control techniques. The project demonstrates how a database system can support secure storage, authenticated access, encrypted queries, and data integrity—all implemented using AES and Order-Preserving Encryption (OPE).


## Features

- User registration and login with password hashing.
- Role-based access control (admin vs. regular user).
- AES encryption for sensitive patient data (e.g., gender and age).
- OPE for range queries on encrypted numeric fields (e.g., weight).
- SHA-256 hashing to ensure data integrity.
- Command-line interface for secure data management.

## Installation

To run the Secure DBaaS project, you need Python and MySQL installed on your machine. It’s recommended to use a virtual environment. Follow these steps to set up the project:

```bash
# Clone the repository
git clone https://github.com/vpriyanca/Data-Security-Project.git
cd Data-Security-Project

# (Optional) Create and activate a virtual environment
python -m venv secure-dbaas-env
source secure-dbaas-env/bin/activate  # On Windows: secure-dbaas-env\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

## Getting Started

### Step 1: Database Setup

Ensure your MySQL server is running locally. The system will automatically create a database named healthdetailsdb with the required tables. You can update MySQL credentials in the script if needed.

### Step 2: Simulate Secure Operations

Open the project in your development environment and run the notebook files in sequence:
- AES Encryption_source_code.ipynb – Handles user authentication, role-based access, AES encryption, and integrity validation.
- Order-Preserving Encryption (OPE)_source_code.ipynb – Enables range queries over encrypted weight data using OPE.

The Faker library is used to generate synthetic patient data.

## Encryption Techniques Used

### AES Encryption
- Encrypts gender and age before storing them in the database.
- Adds random padding to increase confidentiality and prevent pattern leakage.

### Order-Preserving Encryption (OPE)
- Applies a simple multiplication operation (encrypted = value * key) to preserve order.
- Allows secure range queries directly on encrypted data.

### SHA-256 Hashing
- Computes a hash for each record to detect unauthorized modifications or data loss.

 ## Project Outcomes

- Successfully implemented AES encryption for gender and age, confirming confidentiality during data storage.
- Verified that order-preserving encryption (OPE) enabled secure and accurate range queries on weight fields.
- Demonstrated role-based access control, restricting sensitive data based on user privileges.
- Ensured data integrity using SHA-256 hashes; unauthorized data edits were flagged as invalid.
- All operations validated using synthetic healthcare records generated via Faker.

## Custom Utility Functions
- encrypt_data_AES() / decrypt_data_AES() – AES-based data security functions.
- simple_ope_encrypt() / simple_ope_decrypt() – Functions to apply or reverse OPE.
- generate_record_hash() – Computes SHA-256 hashes for integrity checks.
- validate_patient_data() – Ensures patient inputs are within expected formats.

 ## Contributing
Contributions to the Secure DBaaS project are welcome. Please fork the repository and open a pull request. For major changes, kindly open an issue first to discuss what you’d like to change.

## Contact

Project Owner: Priyanka Vyas
Email: vpriyanca617@gmail.com

## Acknowledgments

This project was made possible with the help of the following tools and libraries:
- Python
- MySQL
- bcrypt
- cryptography
- Faker
- Google Colab
- Jupyter Notebook

Thanks to all contributors and open-source libraries that supported this work.
