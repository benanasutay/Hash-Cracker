#!/usr/bin/env python3
"""
Hash Cracker - Multi-threaded Dictionary Attack Tool
Supports: MD5, SHA-1, SHA-256
Purpose: Educational/Penetration Testing
"""

import hashlib
import argparse
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import time

class HashCracker:
    def __init__(self, hash_value, hash_type, wordlist_path, threads=4):
        self.hash_value = hash_value.lower().strip()
        self.wordlist_path = Path(wordlist_path)
        self.threads = threads
        self.found = False
        self.result = None
        self.lock = Lock()
        self.attempts = 0
        
        # Hash fonksiyonları
        self.hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256
        }
        
        # Hash tipini otomatik tespit et
        if hash_type is None:
            self.hash_type = self.detect_hash_type(self.hash_value)
            print(f"[*] Hash tipi otomatik tespit edildi: {self.hash_type.upper()}")
        else:
            self.hash_type = hash_type.lower()
            if self.hash_type not in self.hash_functions:
                raise ValueError(f"Desteklenmeyen hash tipi: {hash_type}")
    
    @staticmethod
    def detect_hash_type(hash_value):
        """Hash uzunluğuna göre tipi otomatik tespit et"""
        hash_length = len(hash_value)
        
        # Hexadecimal kontrolü
        try:
            int(hash_value, 16)
        except ValueError:
            raise ValueError(f"Geçersiz hash formatı: Hash hexadecimal olmalıdır")
        
        # Hash uzunluğuna göre tip belirleme
        hash_types = {
            32: 'md5',      # MD5: 128 bit = 32 hex char
            40: 'sha1',     # SHA-1: 160 bit = 40 hex char
            64: 'sha256'    # SHA-256: 256 bit = 64 hex char
        }
        
        if hash_length not in hash_types:
            raise ValueError(
                f"Bilinmeyen hash uzunluğu: {hash_length} karakter\n"
                f"Desteklenen uzunluklar: 32 (MD5), 40 (SHA-1), 64 (SHA-256)"
            )
        
        return hash_types[hash_length]
    
    def hash_password(self, password):
        """Şifreyi belirtilen algoritma ile hashle"""
        hash_func = self.hash_functions[self.hash_type]
        return hash_func(password.encode('utf-8', errors='ignore')).hexdigest()
    
    def check_password(self, password):
        """Şifreyi kontrol et"""
        with self.lock:
            self.attempts += 1
        
        if self.found:
            return None
        
        hashed = self.hash_password(password)
        
        if hashed == self.hash_value:
            with self.lock:
                if not self.found:
                    self.found = True
                    self.result = password
            return password
        return None
    
    def process_chunk(self, passwords):
        """Şifre bloğunu işle"""
        for password in passwords:
            if self.found:
                return None
            result = self.check_password(password)
            if result:
                return result
        return None
    
    def count_lines(self):
        """Wordlist satır sayısını hızlıca say"""
        count = 0
        with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in f:
                count += 1
        return count
    
    def read_wordlist_generator(self, batch_size=10000):
        """Wordlist'i generator ile oku (RAM optimizasyonu)"""
        batch = []
        with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if password:
                    batch.append(password)
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
            if batch:
                yield batch
    
    def crack(self):
        """Ana kırma fonksiyonu - RAM optimizasyonlu"""
        if not self.wordlist_path.exists():
            raise FileNotFoundError(f"Wordlist bulunamadı: {self.wordlist_path}")
        
        print(f"[*] Hash Cracker Başlatılıyor...")
        print(f"[*] Hash Tipi: {self.hash_type.upper()}")
        print(f"[*] Hedef Hash: {self.hash_value}")
        print(f"[*] Wordlist: {self.wordlist_path}")
        print(f"[*] Thread Sayısı: {self.threads}")
        print(f"[*] Saldırı başlatılıyor...\n")
        
        # Wordlist boyutunu say
        print(f"[*] Wordlist analiz ediliyor...")
        total_passwords = self.count_lines()
        print(f"[*] Toplam {total_passwords:,} şifre tespit edildi")
        print(f"[*] RAM optimizasyonu: Streaming mode aktif\n")
        
        start_time = time.time()
        batch_size = 10000  # Her seferinde 10K şifre işle
        
        try:
            # Streaming ile wordlist'i oku (RAM tasarrufu)
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for batch in self.read_wordlist_generator(batch_size):
                    if self.found:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    
                    # Batch'i chunk'lara böl
                    chunk_size = max(100, len(batch) // self.threads)
                    chunks = [batch[i:i + chunk_size] for i in range(0, len(batch), chunk_size)]
                    
                    # Thread'lere dağıt
                    futures = [executor.submit(self.process_chunk, chunk) for chunk in chunks]
                    
                    for future in as_completed(futures):
                        if self.found:
                            break
                        result = future.result()
                        if result:
                            break
                    
                    # Progress göster
                    if self.attempts % 50000 == 0:
                        elapsed = time.time() - start_time
                        rate = self.attempts / elapsed if elapsed > 0 else 0
                        print(f"[*] İlerleme: {self.attempts:,} / {total_passwords:,} | Hız: {rate:.0f} hash/s", end='\r')
            
            elapsed_time = time.time() - start_time
            
            print(f"\n{'='*60}")
            if self.found:
                print(f"[+] ŞİFRE BULUNDU!")
                print(f"[+] Hash: {self.hash_value}")
                print(f"[+] Şifre: {self.result}")
                print(f"[+] Deneme Sayısı: {self.attempts:,}")
                print(f"[+] Süre: {elapsed_time:.2f} saniye")
                print(f"[+] Hız: {self.attempts/elapsed_time:.2f} hash/saniye")
            else:
                print(f"[-] Şifre bulunamadı")
                print(f"[-] Toplam Deneme: {self.attempts:,}")
                print(f"[-] Süre: {elapsed_time:.2f} saniye")
            print(f"{'='*60}")
            
            return self.result
            
        except KeyboardInterrupt:
            print("\n[!] İşlem kullanıcı tarafından durduruldu")
            return None
        except Exception as e:
            print(f"\n[!] Hata: {e}")
            return None


def create_sample_wordlist():
    """Örnek wordlist oluştur"""
    sample_passwords = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "1234567", "letmein", "trustno1", "dragon",
        "baseball", "111111", "iloveyou", "master", "sunshine",
        "ashley", "bailey", "passw0rd", "shadow", "123123"
    ]
    
    with open("sample_wordlist.txt", "w") as f:
        f.write("\n".join(sample_passwords))
    
    print("[*] Örnek wordlist oluşturuldu: sample_wordlist.txt")


def main():
    banner = """
    ╔═══════════════════════════════════════════╗
    ║      Hash Cracker v1.0                    ║
    ║      MD5 | SHA-1 | SHA-256                ║
    ║      Educational/Pentesting Tool          ║
    ╚═══════════════════════════════════════════╝
    """
    print(banner)
    
    parser = argparse.ArgumentParser(
        description="Multi-threaded Hash Cracker Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  # Otomatik hash tipi tespiti
  %(prog)s -H 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt
  
  # Manuel hash tipi belirtme
  %(prog)s -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w wordlist.txt
  %(prog)s -H 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -t sha1 -w rockyou.txt -T 8
  
  # Örnek wordlist oluştur
  %(prog)s --create-sample
        """
    )
    
    parser.add_argument('-H', '--hash', help='Kırılacak hash değeri')
    parser.add_argument('-t', '--type', choices=['md5', 'sha1', 'sha256'], 
                       help='Hash tipi (belirtilmezse otomatik tespit edilir)')
    parser.add_argument('-w', '--wordlist', help='Wordlist dosya yolu')
    parser.add_argument('-T', '--threads', type=int, default=4,
                       help='Thread sayısı (varsayılan: 4)')
    parser.add_argument('--create-sample', action='store_true',
                       help='Örnek wordlist oluştur')
    
    args = parser.parse_args()
    
    # Örnek wordlist oluştur
    if args.create_sample:
        create_sample_wordlist()
        return
    
    # Argüman kontrolü
    if not all([args.hash, args.wordlist]):
        parser.print_help()
        print("\n[!] Hata: -H ve -w parametreleri zorunludur")
        print("[*] Hash tipi belirtilmezse otomatik tespit edilir")
        print("[*] Örnek wordlist için: python hash_cracker.py --create-sample")
        sys.exit(1)
    
    try:
        # Hash cracker'ı başlat
        cracker = HashCracker(
            hash_value=args.hash,
            hash_type=args.type,
            wordlist_path=args.wordlist,
            threads=args.threads
        )
        
        result = cracker.crack()
        sys.exit(0 if result else 1)
        
    except Exception as e:
        print(f"[!] Fatal Hata: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
