# aescrypt
AES256-GCM encryption tool
#Installation
git clone https://github.com/gcasale82/aescrypt.git
pip3 install -r requirements
This is an encryption tool using AES256 mode GCM for encrypting files or folders.After encryption and decryption password and keys will we wiped in memory overwriting many times.
After encryption original file is wiped with secure deletion.
Scrypt  password-based key derivation function is used instead of popular PBKDF2 in order to minimize brute force attacks , since it is designed to make it costly to perform large-scale custom hardware attacks by requiring large amounts of memory and CPU resources.
(more info at http://www.tarsnap.com/scrypt/scrypt.pdf)
####Usage#####
![image](https://user-images.githubusercontent.com/81979394/207140098-d8cdf701-474e-4140-abb3-3395fa10bd81.png)
