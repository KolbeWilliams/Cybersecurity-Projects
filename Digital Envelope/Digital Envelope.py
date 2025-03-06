import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from PyQt6.QtWidgets import QMainWindow, QWidget, QGridLayout, \
QLabel, QLineEdit, QPushButton, QApplication, QComboBox

#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#
#https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.AES#

#GUI Main Class
class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.gen_senders_keys()
        self.gen_receivers_keys()
        #Initialize Main Window
        self.setWindowTitle("Digital Envelope")
        self.setFixedSize(800, 300)
        self.setStyleSheet(
            "font-family: garamond; \
             color: white; \
             font-size: 32px; \
             background-color: #663399;")        

        #Widgets       
        container = QWidget()
        self.setCentralWidget(container)
        self.line_input = QLineEdit()
        self.line_output = QLineEdit()
        label_input = QLabel(text="Input:")
        label_output = QLabel(text="Output:")
        options = ["Encrypt", "Decrypt"]
        self.combo_box = QComboBox()
        self.combo_box.addItems(options)
        button = QPushButton(text="Enter")
        
        #Format
        button.setStyleSheet("border-radius: 12px; background-color: black;")
        self.line_input.setStyleSheet("background-color: white; color: black")
        self.line_output.setStyleSheet("background-color: white; color: black")
        
        #Layout        
        layout = QGridLayout()              
        layout.addWidget(label_input, 0, 0)
        layout.addWidget(self.line_input, 1, 0)   
        layout.addWidget(label_output, 2, 0)         
        layout.addWidget(self.line_output, 3, 0)
        layout.addWidget(self.combo_box, 4, 0)
        layout.addWidget(button, 5, 0)        
        container.setLayout(layout)

        #Signals
        button.clicked.connect(self.button_clicked)              
    
    #Events
    def button_clicked(self):       
        input_msg = self.line_input.text()
        
        i = self.combo_box.currentIndex()
        if (i == 0):
            output_msg = self.encrypt_digital_env(input_msg)
        if (i == 1):
            output_msg = self.decrypt_digital_env(input_msg)
            
        self.line_output.setText(output_msg)

##########################CODE HERE############################################   
    def encrypt_digital_env(self, plaintext):
        plaintext = plaintext.encode()
        key, iv, ciphertext = self.symmetric_encryption(plaintext)
        key_iv = key + iv
        encrypted_key = self.asymmetric_encrypt(key_iv)
        signature = self.sign(plaintext)
        digital_envelope = self.package_envelope(encrypted_key, ciphertext, signature)
        digital_envelope = digital_envelope.hex()
        return digital_envelope        
    
    def decrypt_digital_env(self, digital_envelope):
        digital_envelope = bytes.fromhex(digital_envelope)
        encrypted_key, ciphertext, signature = self.unpackage_envelope(digital_envelope)
        decrypted_key = self.asymmetric_decrypt(encrypted_key)
        plaintext = self.symmetric_decryption(ciphertext, decrypted_key)
       
        if (self.verify_signature(signature, plaintext)): #####{Verified}#####
            plaintext = plaintext.decode()
            return plaintext #####{Plaintext}#####
        else:
            return "Invalid Signature"

    def gen_senders_keys(self):
        self.senders_private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
        self.senders_public_key = self.senders_private_key.public_key()
        
        
    def gen_receivers_keys(self):
        self.receivers = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
        self.receivers_public_key = self.senders_private_key.public_key()
        
    def symmetric_encryption(self, plaintext):
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        #cipher.algorithm
        padded_message = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return (key, iv, ciphertext)
    
    def symmetric_decryption(self, ciphertext, decrypted_key):
        key = decrypted_key[:32]
        iv = decrypted_key[32:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
        return plaintext
    
    def asymmetric_encrypt(self, key_iv):
        encrypted_key = self.senders_public_key.encrypt(
            key_iv,
            padding.OAEP(
                mgf = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
            )
        )
        return encrypted_key
    
    def asymmetric_decrypt(self, encrypted_key):
        decrypted_key = self.senders_private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf = padding.MGF1(algorithm = hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
            )
        )
        return decrypted_key

    def sign(self, plaintext):
        signature = self.senders_private_key.sign(
            plaintext,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, signature, plaintext):
        try:
            self.senders_public_key.verify(
                signature,
                plaintext,
                padding.PSS(
                    mgf = padding.MGF1(hashes.SHA256()),
                    salt_length = padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    def package_envelope(self, encrypted_key, ciphertext, signature):
        digital_envelope = encrypted_key + ciphertext + signature
        return digital_envelope
    
    def unpackage_envelope(self, digital_envelope):
        encrypted_key = digital_envelope[:256]
        
        ciphertext = digital_envelope[256:-256]
        #ciphertext = digital_envelope[256:272]
        
        signature = digital_envelope[-256:]
        #signature = digital_envelope[272:]
        return (encrypted_key, ciphertext, signature)
###############################################################################

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()

