import sys
from typing import Self
from PyQt6.QtWidgets import QApplication, QMainWindow, QTableWidget, QTableWidgetItem, QHBoxLayout, QWidget, QLabel
from PyQt6.QtCore import Qt

class User:
    def __init__(self, name, role):
        self.name = name
        self.role = role

class Role:
    def __init__(self, name, object_name):
        self.name = name
        self.object_name = object_name
        self.permissions = set()
        
    def set_permission(self, permission):
        self.permissions.add(permission)
        
    def get_permissions(self):
        return self.permissions        
    
class Engineer(Role):
    def __init__(self, name, object_name):
        super().__init__(name, object_name)
        self.set_permission("read_code")
        
class ProductionEngineer(Engineer):
    def __init__(self, name, object_name):
        super().__init__(name, object_name)
        self.set_permission("deploy_code")
        
class QualityEngineer(Engineer):
    def __init__(self, name, object_name):
        super().__init__(name, object_name)
        self.set_permission("test_code")

class ProjectLead(ProductionEngineer, QualityEngineer):
    def __init__(self, name, object_name):
        super().__init__(name, object_name)
        self.set_permission("manage_project")

class Director(ProjectLead):
    def __init__(self, name, object_name):
        super().__init__(name, object_name)
        self.set_permission("assign_projects")

        
class Session:
    def __init__(self):
        self.users = []
        self.users.append(User('DIR', Director('Director', 'All Projects')))
        self.users.append(User('PL1', ProjectLead('Project Lead', 'Project 1')))
        self.users.append(User('PL2', ProjectLead('Project Lead', 'Project 2')))
        self.users.append(User('PE1', ProductionEngineer('Production Engineer', 'Project 1')))
        self.users.append(User('PE2', ProductionEngineer('Production Engineer', 'Project 2')))
        self.users.append(User('QE1', QualityEngineer('Quality Engineer', 'Project 1')))
        self.users.append(User('QE2', QualityEngineer('Quality Engineer', 'Project 2')))
        self.users.append(User('E1', Engineer(' Engineer', 'Project 1')))
        self.users.append(User('E2', Engineer(' Engineer', 'Project 2')))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RBAC")
        self.setFixedSize(1100, 400)
        self.setStyleSheet(
            "font-family: garamond; \
             color: white; \
             font-size: 12px; \
             background-color: #663399;")        

        self.session = Session()
        # Create widgets
        self.roles_table = QTableWidget()
        self.users_table = QTableWidget()

        # Set up roles table
        self.roles_table.setColumnCount(2)
        self.roles_table.setHorizontalHeaderLabels(["Role", "Permissions"])
        self.roles_table.setSortingEnabled(True)
        self.roles_table.setStyleSheet("background-color: white; color: black")
      
        # Set up users table
        self.users_table.setColumnCount(3)
        self.users_table.setHorizontalHeaderLabels(["User", "Role", "Object Name"])
        self.users_table.setSortingEnabled(True)
        #self.users_table.setMinimumWidth(400)
        self.users_table.setStyleSheet("background-color: white; color: black")
        
        # Populate tables
        self.populate_roles_table()
        self.populate_users_table()

        # Layout
        layout = QHBoxLayout()
        layout.addWidget(self.roles_table)
        layout.addWidget(self.users_table)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def populate_roles_table(self):
        seen_roles = set() 

        row = 0
        for user in self.session.users:
            role = user.role

            if role.name not in seen_roles:
                self.roles_table.insertRow(row)
                self.roles_table.setItem(row, 0, QTableWidgetItem(role.name))
                permissions_item = QTableWidgetItem(", ".join(role.get_permissions()))
                permissions_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                self.roles_table.setItem(row, 1, permissions_item)
                row += 1
                seen_roles.add(role.name) 
        self.roles_table.resizeColumnsToContents()
        
    def populate_users_table(self):
        row = 0
        for user in self.session.users:
            self.users_table.insertRow(row)
            self.users_table.setItem(row, 0, QTableWidgetItem(user.name))
            self.users_table.setItem(row, 1, QTableWidgetItem(user.role.name))
            self.users_table.setItem(row, 2, QTableWidgetItem(user.role.object_name))
            row += 1
        self.users_table.resizeColumnsToContents()   

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
