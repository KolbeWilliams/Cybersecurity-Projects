import os
import re
import sys
import time

from PyQt6.QtWidgets import QMainWindow, QWidget, QMessageBox,\
QLabel, QLineEdit, QVBoxLayout, QPushButton, QApplication

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.hashes import SHA1

#https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.scrypt.Scrypt
#https://cryptography.io/en/latest/hazmat/primitives/twofactor/#cryptography.hazmat.primitives.twofactor.InvalidToken
#https://docs.python.org/3/library/re.html
#https://www.w3schools.com/python/python_regex.asp

#GUI Main Class
class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.username_list = []
        self.pw_list = []
        self.salt_list = []
        #Initialize Main Window
        self.setWindowTitle("Two-factor Authenctication")
        self.setFixedSize(400, 500)
        self.setStyleSheet(
            "font-family: garamond; \
             color: white; \
             font-size: 32px; \
             background-color: #663399;")        

        #Widgets       
        container = QWidget()
        self.setCentralWidget(container)
        self.line_username = QLineEdit()
        self.line_pw = QLineEdit()
        self.line_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.line_dpw = QLineEdit()
        self.line_dpw.setEchoMode(QLineEdit.EchoMode.Password)
        self.line_token = QLineEdit()
        label_signup = QLabel(text="Create an Account")
        label_username = QLabel(text="Username:")
        label_pw = QLabel(text="Password:")
        label_dpw = QLabel(text="Confirm Password:")
        label_token = QLabel(text="Token:")
        button_create = QPushButton(text="Create")
        button_login = QPushButton(text="Login")
        
        #Format
        button_create.setStyleSheet("border-radius: 12px; background-color: black;")
        button_login.setStyleSheet("border-radius: 12px; background-color: black;")
        self.line_username.setStyleSheet("background-color: white; color: black")
        self.line_pw.setStyleSheet("background-color: white; color: black")
        self.line_dpw.setStyleSheet("background-color: white; color: black")
        self.line_token.setStyleSheet("background-color: white; color: black")
        
        #Layout        
        layout = QVBoxLayout()
        layout.addWidget(label_signup)
        layout.addWidget(label_username)
        layout.addWidget(self.line_username)   
        layout.addWidget(label_pw)         
        layout.addWidget(self.line_pw)
        layout.addWidget(label_dpw)         
        layout.addWidget(self.line_dpw)
        layout.addWidget(button_create)
        layout.addWidget(label_token)         
        layout.addWidget(self.line_token)       
        layout.addWidget(button_login)
        container.setLayout(layout)

        #Signals
        button_create.clicked.connect(self.button_create_clicked)
        button_login.clicked.connect(self.button_login_clicked)
    
    #Events
    def button_create_clicked(self):       
        username = self.line_username.text()
        pw = self.line_pw.text()
        dpw = self.line_dpw.text()
        if not self.verify_username(username):
            mb = QMessageBox.critical(self,
                "Invalid Username",
                "Username must be between 4-12 characters and " +
                "contain only lowercase letters and numbers."
            )            
            return
        if not self.verify_pw(pw):
            mb = QMessageBox.critical(self,
                "Invalid Password",
                "Password must be at least 8 characters long and contain " + 
                "at least one uppercase letter, one lowercase letter, " +
                "one number, and one special character."
            )            
            return
        if not self.compare_pws(pw, dpw):
            mb = QMessageBox.critical(self,
                "Invalid Passwords",
                "Passwords must match."
            )            
            return
        token = self.gen_token()
        self.scrypt_derive(username, pw)        
        mb = CustomMessageBox()
        mb.line_edit.setText(token)
        mb.exec()
    
    def button_login_clicked(self):
        username = self.line_username.text()
        pw = self.line_pw.text()
        token = self.line_token.text()
        if not self.verify_username(username):
            mb = QMessageBox.critical(self,
                "Invalid Username",
                "Username must be between 4-12 characters and " +
                "contain only lowercase letters and numbers."
            )            
            return
        if not self.verify_pw(pw):
            mb = QMessageBox.critical(self,
                "Invalid Password",
                "Password must be at least 8 characters long and contain " + 
                "at least one uppercase letter, one lowercase letter, " +
                "one number, and one special character."
            )            
            return
        credentials = self.find_credentials(username)
        if not credentials[0]:           
            mb = QMessageBox.critical(self,
                "Invalid Username",
                "Username not found."
            )            
            return
        i = credentials[1]
        _, stored_pw, salt= self.lookup_credentials(i)
        if not self.verify_token(token):
            mb = QMessageBox.critical(self,
                "Invalid Token",
                "Token expired or invalid"
            )            
            return
        if self.scrypt_verify(pw, stored_pw, salt):
            mb = QMessageBox.information(self,
                "Authentication",
                "Access Granted"
            )            
            return
        else:
            mb = QMessageBox.critical(self,
                "Authentication",
                "Access Denied"
            )            
            return
        
#########################Code Here###############################################

    # Function: verify_username
    # Pre:   Parameter username must be a string
    #        Ensure library imports (re)
    # Post:  If username parameter meets the folowing criteria, return True:
    #             Between 4 and 12 characters long
    #             Contains only lowercase letters and numbers
    #        Otherwise return False
    def verify_username(self, username):
        regex = r"^[a-z0-9]{4,12}$"
        return re.match(regex, username)

    # Function: verify_pw
    # Pre:   Parameter pw must be a string
    #        Ensure library imports (re)
    # Post:  If password parameter meets the folowing criteria return True:
    #             Password must be at least 8 characters long and contain 
    #             at least one uppercase letter, one lowercase letter, 
    #             one number, and  one special character.
    #        Otherwise return False    
    def verify_pw(self, pw):
        regex = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[~!@#$%^&*()_+])[A-Za-z\d~!@#$%^&*()_+]{8,}$"
        return re.match(regex, pw)
    
    # Function: compare_pws
    # Pre:   Password parameter and duplicate password parameter must be strings
    # Post:  If password parameter and duplicate password parameter are identical return True
    #         Otherwise return False
    def compare_pws(self, pwd, dpw):
        return pwd == dpw

    # Function: gen_token
    # Pre:   Ensure library imports (os, TOTP, SHA1, time)
    # Post:  Returns a string of time-based one-time password token of 8 digits
    def gen_token(self):
        key = os.urandom(20)
        self.totp = TOTP(key, 8, SHA1(), 30)
        time_value = time.time()
        totp_value = self.totp.generate(time_value)
        return totp_value.decode()
        
    
    # Function: verify_token
    # Pre:   Ensure library imports (os, TOTP, SHA1, time)
    #        Parameter token is a string representing the TOTP token to be verified
    # Post:  If token parameter is valid for current time window return True
    #        Otherwise return False
    #        time_value atrribute is updated with current time
    def verify_token(self, token):
        try:
            #add time and verify
            time_value = time.time()
            self.totp.verify(token.encode(), time_value)
            return True
        except:
            return False

    # Function: scrypt_derive
    # Pre:   Ensure library imports (os, Scrypt)
    #        Parameter username must be a string
    #        Parameter pw must be a string
    #        Method self.store_credentials used to store username, pw, and salt (pass to store credentials)
    # Post:  The function derives a password hash using the Scrypt algorithm
    #        The credentials are stored   
    def scrypt_derive(self, username, pw):
        salt = os.urandom(16)
        # derive
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )
        key = kdf.derive(pw.encode())
        self.store_credentials(username, key, salt)
    
    # Function: scrypt_verify
    # Pre:   Ensure library imports (Scrypt)
    #        Parameter pw must be a string
    #        Parameter stored_pw previously stored password hash
    #        Parameter salt must be a string representing the salt used during password hashing
    # Post:  If the password parameter matches stored password hash return True
    #        Otherwise return False   
    def scrypt_verify(self, pw, stored_pw, salt):
        try:
            # verify
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
            )
            kdf.verify(pw.encode(), stored_pw)
            return True
        except:
            return False

    # Function: store_credentials
    # Pre:   The self.username_list, self.pw_list, and self.salt_list attributes 
    #           are defined and accessible within the class.
    #        Parameters username, pw, and salt must be strings 
    # Post:  Parameters appended to corresponding lists         
    def store_credentials(self, username, pw, salt):
        self.username_list.append(username)
        self.pw_list.append(pw)
        self.salt_list.append(salt)

    # Function: find_credentials
    # Pre:   The self.username_list attributes 
    #           is defined and accessible within the class.
    #        Parameter username must be a string
    # Post:  If the username is found in the self.username_list, 
    #           the function returns a tuple (True, i), 
    #           where i is the index of the username in the list.
    #        Otherwise the username is not found in the self.username_list, 
    #           the function returns a tuple (False, None).   
    def find_credentials(self, username):
        try:
            i = self.username_list.index(username)
            return (True, i)
        except:
            return (False, None)


    # Function: lookup_credentials
    # Pre:   The self.username_list, self.pw_list, and self.salt_list attributes 
    #           are defined and accessible within the class.
    #        Parameter i an integer representing the index of the credentials to retrieve.
    # Post:  Returns a tuple containing 
    #           the username, password, and salt at that index.     
    def lookup_credentials(self, i):
        return(self.username_list[i], self.pw_list[i], self.salt_list[i])

#############################################################################    

class CustomMessageBox(QMessageBox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setStyleSheet(
            "font-family: garamond; \
             color: white; \
             font-size: 32px; \
             background-color: #663399;")
        self.setWindowTitle("Account Created")
        label = QLabel(text="Token:")
        self.setText("Verified")
        self.setIcon(QMessageBox.Icon.Information)
        self.line_edit = QLineEdit()
        self.line_edit.setFixedWidth(130)
        self.layout().addWidget(label)
        self.layout().addWidget(self.line_edit)
        
def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()


