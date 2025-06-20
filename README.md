# Secure DBaaS Project

## Overview
Secure DBaaS is a secure database-as-a-service simulation project focused on protecting healthcare data through encryption and access control. It demonstrates how a database system can support secure storage, user authentication, role-based access, and query functionality on encrypted data using AES and Order-Preserving Encryption (OPE).

## Features
- User registration and login with password hashing.
- Role-based access control (admin vs. regular user).
- AES encryption for sensitive patient attributes (gender, age).
- OPE applied on numerical fields to enable range queries on encrypted data.
- SHA-256 hashing to ensure data integrity.
- Command-line interface for interaction and record management.

## Installation
To run the Secure DBaaS project, you need to have Python and MySQL installed on your machine. It's recommended to use a virtual environment. Follow these steps to set up the project environment:

```bash
# Clone the repository
git clone https://github.com/vpriyanca/Data-Security-Project.git
cd Data-Security-Project

# (Optional) Setup a virtual environment
python -m venv secure-dbaas-env
source secure-dbaas-env/bin/activate  # On Windows, use `secure-dbaas-env\Scripts\activate`

# Install the required packages
pip install -r requirements.txt
