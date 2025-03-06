#Lab 02 Base Code
# pip install PyQt6
# pip install Cryptography
# pip install opencv-contrib-python

# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#

#Imports
import os
import sys
from uu import decode
import cv2
import string
import numpy as np
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import QMainWindow, QWidget, QGridLayout, \
QLabel, QLineEdit, QPushButton, QApplication, QComboBox
from PyQt6 import QtCore
from PyQt6.QtCore import Qt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

#GUI Main Class
class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        #Initialize Main Window
        self.setWindowTitle("Crytography")
        self.setFixedSize(1920, 1080)
        self.setStyleSheet(
            "font-family: garamond; \
             color: white; \
             font-size: 32px; \
             background-color: #663399;")
       
        #Initialize Key, Number Used Once and Initialization Vector
        self.aes_key = os.urandom(32)
        self.des3_key = os.urandom(24)
        self.iv = os.urandom(8)        
        self.nonce = os.urandom(16)

        #Widgets      
        container = QWidget()
        subcontainer = QWidget()
        label_input_file = QLabel(text="Input File:")
        label_output_file = QLabel(text="Output File:")
       
        self.label_img = QLabel()
        input_image = "top_secret.png"
        pixmap = QPixmap(input_image)
        self.label_img.setPixmap(pixmap)

        self.line_input_file = QLineEdit()
        self.line_output_file = QLineEdit()
        button_img = QPushButton(text="Enter")
        options = ["AES-ECB Encrypt", "AES-ECB Decrypt", "AES-CTR Encrypt", "AES-CTR Decrypt"]
        self.combo_box_img = QComboBox()
        self.combo_box_img.addItems(options)

        label_input_msg = QLabel(text="Input Message:")
        label_output_msg = QLabel(text="Output Message:")
        self.line_input_msg = QLineEdit()
        self.line_output_msg = QLineEdit()
        button_msg = QPushButton(text="Enter")
        options = ["3DES-CBC Encrypt", "3DES-CBC Decrypt"]
        self.combo_box_msg = QComboBox()
        self.combo_box_msg.addItems(options)
       
        #Format
        button_img.setStyleSheet("border-radius: 12px; background-color: black;")
        button_msg.setStyleSheet("border-radius: 12px; background-color: black;")
        self.line_input_file.setStyleSheet("background-color: white; color: black")
        self.line_output_file.setStyleSheet("background-color: white; color: black")
        self.line_input_msg.setStyleSheet("background-color: white; color: black")
        self.line_output_msg.setStyleSheet("background-color: white; color: black")
       
        #Layout        
        sublayout = QGridLayout()
        layout = QGridLayout()
       
        sublayout.addWidget(label_input_file, 0, 0)
        sublayout.addWidget(self.line_input_file, 0, 1)
        sublayout.addWidget(label_output_file, 1, 0)
        sublayout.addWidget(self.line_output_file, 1, 1)      
        sublayout.addWidget(self.combo_box_img, 2,0)
        sublayout.addWidget(button_img, 2, 1)
       
        sublayout.addWidget(label_input_msg, 3, 0)
        sublayout.addWidget(self.line_input_msg, 3, 1)
        sublayout.addWidget(label_output_msg, 4, 0)
        sublayout.addWidget(self.line_output_msg, 4, 1)      
        sublayout.addWidget(self.combo_box_msg, 5,0)
        sublayout.addWidget(button_msg, 5, 1)
       
        subcontainer.setLayout(sublayout)
       
        layout.addWidget(subcontainer, 0, 0)
        layout.addWidget(self.label_img, 0,1)
       
        container.setLayout(layout)

        #Signals
        button_img.clicked.connect(self.button_img_clicked)
        button_msg.clicked.connect(self.button_msg_clicked)
        self.setCentralWidget(container)
   
    #Events
    def button_img_clicked(self):      
       
       input_file = self.line_input_file.text()
       output_file = self.line_output_file.text()
       
       i = self.combo_box_img.currentIndex()
       if (i == 0):
           self.aes_ecb_encrypt_img(input_file, output_file)
       if (i == 1):
           self.aes_ecb_decrypt_img(input_file, output_file)
       if (i == 2):
           self.aes_ctr_encrypt_img(input_file, output_file)
       if (i == 3):
           self.aes_ctr_decrypt_img(input_file, output_file)

       pixmap = QPixmap(output_file)
       self.label_img.setPixmap(pixmap)
       
    def button_msg_clicked(self):
       input_msg = self.line_input_msg.text()
       output_msg = ""
       
       i = self.combo_box_msg.currentIndex()
       if (i == 0):
           output_msg = self.des3_cbc_encrypt_msg(input_msg)
       if (i == 1):
           output_msg = self.des3_cbc_decrypt_msg(input_msg)

       self.line_output_msg.setText(output_msg)

##########################CODE HERE############################################      
    def aes_ecb_encrypt_img(self, input_file, output_file):
        #open Image of input_file
        img = cv2.imread(input_file)
        
        #Flatten and convert to bytes
        img_data = img.flatten().tobytes()
        
        #perform the encryption
        cipher = Cipher(algorithms.AES(self.aes_key), modes.ECB())
        encryptor = cipher.encryptor()
        encrypted_data =encryptor.update(img_data) + encryptor.finalize()
       
        #Convert from bytes to image (np.formbuffer, .reshape(img.shape))
        encrypted_arr = np.frombuffer(encrypted_data, dtype=np.uint8)
        encrypted_arr = encrypted_arr.reshape(img.shape)
       
       #save the image to output_file
        cv2.imwrite(output_file, encrypted_arr)

    def aes_ecb_decrypt_img(self, input_file, output_file):
        #open Image of input_file
        img = cv2.imread(input_file)
        
        #Flatten and convert to bytes
        img_data = img.flatten().tobytes()
        
        #perform the decryption
        cipher = Cipher(algorithms.AES(self.aes_key), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(img_data) + decryptor.finalize()
        
        #Convert from bytes to image (np.formbuffer, .reshape(img.shape))
        decrypted_arr = np.frombuffer(decrypted_data, dtype=np.uint8)
        decrypted_arr = decrypted_arr.reshape(img.shape)
        
        #save the image to output_file
        cv2.imwrite(output_file, decrypted_arr)

    def aes_ctr_encrypt_img(self, input_file, output_file):
        #open Image of input_file
        img = cv2.imread(input_file)
        
        #Flatten and convert to bytes
        img_data = img.flatten().tobytes()
        
        #perform the encryption
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(self.nonce))
        encryptor = cipher.encryptor()
        encrypted_data =encryptor.update(img_data) + encryptor.finalize()
       
        #Convert from bytes to image (np.formbuffer, .reshape(img.shape))
        encrypted_arr = np.frombuffer(encrypted_data, dtype=np.uint8)
        encrypted_arr = encrypted_arr.reshape(img.shape)
       
       #save the image to output_file
        cv2.imwrite(output_file, encrypted_arr)

    def aes_ctr_decrypt_img(self, input_file, output_file):
        #open Image of input_file
        img = cv2.imread(input_file)
        
        #Flatten and convert to bytes
        img_data = img.flatten().tobytes()
        
        #perform the decryption
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(self.nonce))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(img_data) + decryptor.finalize()
       
        #Convert from bytes to image (np.formbuffer, .reshape(img.shape))
        decrypted_arr = np.frombuffer(decrypted_data, dtype=np.uint8)
        decrypted_arr = decrypted_arr.reshape(img.shape)
        
        #save the image to output_file
        cv2.imwrite(output_file, decrypted_arr)

    def des3_cbc_encrypt_msg(self, plaintext):
        plaintext = plaintext.encode()
        #TripleDES
        
        cipher = Cipher(algorithms.TripleDES(self.des3_key), modes.CBC(self.iv))
        
        padder = padding.PKCS7(cipher.algorithm.block_size).padder()
        padded_message = padder.update(plaintext) + padder.finalize()
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        
        
        ciphertext = ciphertext.hex()
        return ciphertext

    def des3_cbc_decrypt_msg(self, ciphertext):
        ciphertext = bytes.fromhex(ciphertext)
        #TripleDES
        #Decryption
        cipher = Cipher(algorithms.TripleDES(self.des3_key), modes.CBC(self.iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(cipher.algorithm.block_size).unpadder()
        unpadded_message = unpadder.update(decrypted_data) + unpadder.finalize()
        
        plaintext = unpadded_message.decode()
        return plaintext
        
###############################################################################
def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
