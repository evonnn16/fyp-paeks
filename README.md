# Lightweight and Privacy Preserving Public-Key Authenticated Encryption with Keyword Search using Type-3 Pairing

## Abstract
 Cloud services and applications available anywhere in this modern era  have increased the demand of users to store data on the cloud, thereby requiring encrypted storage to secure sensitive data. With encryption applied to the stored  data, advanced mechanisms for searching over encrypted data without decryption are necessary to preserve data privacy, especially in scenarios where third-party cloud service providers are involved. If the keywords used for searching data and the search results are known by the cloud server, the user’s privacy may be leaked. Hence, a searchable encryption scheme such as Public-key Authenticated Encryption with Keyword Search (PAEKS) needs to be implemented for confidential searching without decryption. In this paper, we upgrade the performance of a lightweight PAEKS scheme that is secure against keyword guessing attacks by reconstructing the scheme in Type-3 pairing. Subsequently, we benchmark the performance gained for the lightweight PAEKS scheme using SS1024 and BN254 curves for Type-1 and Type-3 pairings, respectively.

## Requirements
 The project is intended to run on Kali Linux 2022 using Python 3.10. The following Python packages are required:
- Flask
- Firebase Admin
- Matplotlib
- PyCryptodome
- Charm-Crypto (https://github.com/JHUISI/charm)

## Usage
To run the PAEKS scheme, use the command: `python PAEKS.py`  
To run performance benchmarking, use the command: `python performance.py`  
To run the email web application that implements PAEKS scheme and hybrid cryptographic scheme (ElGamal + AES-GCM), use the command: `python app.py`
