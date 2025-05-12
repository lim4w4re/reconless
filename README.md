![reconless](https://github.com/user-attachments/assets/3fd59576-7943-49a3-82df-2deff841c76d)

> Reconless is a Python-based tool designed to assist cybersecurity professionals during offensive security assessments. It acts as a lightweight DNS server (listener) to establish a data exfiltration channel. Reconless can receive and parse communications through "A" DNS requests using subdomains as the transport layer.

## 💡 Features
- Core:
    - Customized domain to receive DNS requests;
    - Data encryption and decryption using ROT13 and/or base32;
    - Powershell Script for use on the client side (sample);
    - Log management and local storage of results.
- Optional:
    - Manual IP configuration for authoritative servers.
 
## 🛠️ To Do
The project is still under development and the next updates will focus on the following tasks:
- [ ] Code refactoring and implementation of good practices (this code is terrible to read 💀)
- [ ] Implementation of error handling and resilience
- [ ] Increased encryption support (I don't know why the hell I put ROT13)
- [ ] Support for defense evasion functions in the generation of example scripts (powershell) and better mechanisms for exfil
      
## 💻 Pre-requisites
The following requirements are necessary to use the tool:
  - Python3.X with pip3/pip/pipx
  - python dnslib package

## 🚀 Installation
To use the tool, simply install the lib dependencies:

🐧 Linux (Debian Based):
```
pip3 install -r requirements.txt
```

## 🔥 How to use
Some examples of using the tool:
  - Default usage: Server will listen for DNS requests with the given domain (-d or --domain options) and store the received logs in a text file (-l or --log options) in the local directory:
    ```
    python3 reconless.py -domain <your-domain> -l
    ```
    ![image](https://github.com/user-attachments/assets/3fd7b6de-4119-465a-8c75-ad0a780bffd3)


  - Reconless can also generate a custom example script written in powershell (-gs or --generated-script options), which collects information about the target host and sends it to the server:
    ```
    python3 reconless.py -d <your-domain> -i <your autoritative IP> -gs
    ```
    ![image](https://github.com/user-attachments/assets/1d1ccb44-4329-4e81-bc0b-06d37a381f2f)

    Example:
    
    ![reconless-gif](https://github.com/user-attachments/assets/64406b28-90d2-41cd-9896-7f2a5ea0d573)


