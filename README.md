## Secure DBaaS Project

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

...

## Getting Started

Step 1: Database Setup
Ensure your MySQL server is running locally. The system will automatically create a database named healthdetailsdb with necessary tables. You may update the MySQL credentials in the script if needed.

Step 2: Simulate Secure Operations
Open the project in your development environment and run the notebook files in order:
	•	AES Encryption_source_code.ipynb – Handles user authentication, role-based access, AES encryption, and integrity checks.
	•	Order-Preserving Encryption (OPE)_source_code.ipynb – Enables range queries over encrypted weight data using OPE.

The Faker library is used to generate synthetic patient data.
