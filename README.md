# Hash Cracker 🔓

![License](https://img.shields.io/badge/License-MIT-green.svg)

High-performance, multi-threaded dictionary attack tool (Hash Cracker) supporting MD5, SHA-1, SHA-256 with auto-algorithm detection.

## Features ✨

* **🚀 Multi-Threaded:** Maximizes CPU usage for high-speed cracking.
* **🧠 Auto-Detect:** Automatically identifies MD5, SHA-1, and SHA-256 algorithms.
* **💾 RAM Optimized:** Uses generators to process large wordlists without memory crashes.
* **🛠️ Easy to Use:** Simple CLI interface with built-in test data generation.

## Interface 📸

Help Menu Interface <img width="1267" height="828" alt="image" src="https://github.com/user-attachments/assets/a1889ce4-9729-4a21-b1ae-b405ba49b756" />

## How to Run? 🚀

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/benanasutay/hash-cracker.git](https://github.com/benanasutay/hash-cracker.git)
    ```

2.  **Navigate to the project directory:**
    ```bash
    cd hash-cracker
    ```

3.  **Run the tool:**
    ```bash
    python hash_cracker.py --help
    ```

## Usage 🎮

* **Crack a hash (Auto-Detect):**
    ```bash
    python hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt
    ```

* **Create a sample wordlist for testing:**
    ```bash
    python hash_cracker.py --create-sample
    ```

## Disclaimer ⚠️
**For Educational Use Only.**
This tool is intended for security research and educational purposes. The author takes no responsibility for misuse.
