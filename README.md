****Secure DBaaS Project**

**Overview**
Secure DBaaS is a secure database-as-a-service simulation project focused on protecting healthcare data through encryption and access control. It demonstrates how a database system can support secure storage, user authentication, role-based access, and query functionality on encrypted data using AES and Order-Preserving Encryption (OPE).

**Features**
	•	User registration and login with password hashing.
	•	Role-based access control (admin vs. regular user).
	•	AES encryption for sensitive patient attributes (gender, age).
	•	OPE applied on numerical fields to enable range queries on encrypted data.
	•	SHA-256 hashing to ensure data integrity.
	•	Command-line interface for interaction and record management.

**Installation**
To run the Secure DBaaS project, you need to have Python and MySQL installed on your machine. It’s recommended to use a virtual environment. Follow these steps to set up the project environment:
# Clone the repository
git clone https://github.com/vpriyanca/Data-Security-Project.git
cd Data-Security-Project
# (Optional) Setup a virtual environment
python -m venv secure-dbaas-env
source secure-dbaas-env/bin/activate  # On Windows, use `secure-dbaas-env\Scripts\activate`
# Install the required packages
pip install -r requirements.txt

**Usage**
This project is structured to simulate a secure healthcare database with encryption and secure query support. Follow the steps below to get started with Secure DBaaS:

**Data Preparation**
Ensure your MySQL server is running locally. The project automatically creates a database named healthdetailsdb along with required tables. You can update MySQL credentials in the script if needed.
The key datasets used in this project are generated during execution using the Faker library.
**Running the System**
To perform encryption, add and retrieve data, and simulate different user roles:
	•	Open the project in your preferred development environment.
	•	Run the notebook files in sequence:
	•	AES Encryption_source_code.ipynb – for login, record encryption, role access, and integrity checks.
	•	Order-Preserving Encryption (OPE)_source_code.ipynb – for performing encrypted range queries.

**Models**
The project demonstrates several core security mechanisms:
**AES Encryption**
	•	Encrypts gender and age using AES before storing them in the database.
	•	Adds random padding to the data to increase confidentiality.
**Order-Preserving Encryption (OPE)**
	•	Applies a simple numeric transformation (value * key) to allow range queries on encrypted weight data.
	•	Ensures the encrypted values maintain their original order for accurate querying.
**SHA-256 Data Integrity**
	•	Generates a unique hash per patient record to detect unauthorized modifications or incomplete retrievals.

**Visualization**
The project includes output screenshots in the notebook to illustrate:
	•	Encrypted and decrypted values for AES and OPE.
	•	Role-based data visibility.
	•	Range query results.
	•	Data integrity checks.

**Custom Functions**
Several utility functions are implemented to support encryption and validation:
	•	simple_ope_encrypt() and simple_ope_decrypt() – for applying/reversing OPE.
	•	encrypt_data_AES() and decrypt_data_AES() – for AES encryption/decryption.
	•	generate_record_hash() – for computing a hash for each record.
	•	validate_patient_data() – to ensure input consistency and cleanliness.

**Contributing**
Contributions to the Secure DBaaS project are welcome. Please follow the standard GitHub pull request process to submit your contributions. For major changes, please open an issue first to discuss what you would like to change.

**Contact**
Project Owner: Priyanka Vyas
Email: vpriyanca617@gmail.com

**Acknowledgments**
This project wouldn’t have been possible without the help of the following tools and libraries:
	•	Python
	•	MySQL
	•	bcrypt
	•	cryptography
	•	Faker
	•	Google Colab
	•	Jupyter Notebook

A huge thanks to all contributors and open-source libraries that made this project possible.
