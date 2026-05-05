import sys
import os
from PyQt5 import QtCore, QtGui, QtWidgets
from des import *
from function import *


class MyWin(QtWidgets.QMainWindow):
    """Главное окно приложения"""
    
    def __init__(self, parent=None):
        """Инициализация главного окна и настройка всех компонентов"""
        QtWidgets.QWidget.__init__(self, parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        
        self.ui.stackedWidget.setCurrentIndex(0)
        
        self.ui.pushButton_gp_key_gener.clicked.connect(self.switch_to_key_generation)
        self.ui.pushButton__gp_encryption.clicked.connect(self.switch_to_encryption)
        self.ui.pushButton_gp_decryption.clicked.connect(self.switch_to_decryption)
        
        self.ui.toolButton_path.clicked.connect(self.select_directory)
        self.ui.pushButton_genKey.clicked.connect(self.generate_keys)
        
        self.ui.toolButton_path_source_file.clicked.connect(self.select_source_file)
        self.ui.toolButton_path_private_key.clicked.connect(self.select_private_key_file)
        self.ui.toolButton_path_sym_key.clicked.connect(self.select_sym_key_file)
        self.ui.toolButton_path_result.clicked.connect(self.select_result_directory)
        self.ui.pushButton_encrypte.clicked.connect(self.encrypt_file)
        
        self.ui.toolButton_path_encrypted.clicked.connect(self.select_encrypted_file)
        self.ui.toolButton_path_private_key_2.clicked.connect(self.select_private_key_file_decrypt)
        self.ui.toolButton_path_sym_key_2.clicked.connect(self.select_sym_key_file_decrypt)
        self.ui.toolButton_path_10.clicked.connect(self.select_result_directory_decrypt)
        self.ui.pushButton_decrypt.clicked.connect(self.decrypt_file)
        
        self.update_status_key_generation("Waiting for information...", None, None)
        self.update_status_encryption("Waiting for information...", None, None, None, None)
        self.update_status_decryption("Waiting for information...", None, None, None, None)
    
    def switch_to_key_generation(self):
        """Переключает интерфейс на страницу генерации ключей"""
        self.ui.stackedWidget.setCurrentIndex(0)
    
    def switch_to_encryption(self):
        """Переключает интерфейс на страницу шифрования"""
        self.ui.stackedWidget.setCurrentIndex(1)
    
    def switch_to_decryption(self):
        """Переключает интерфейс на страницу дешифрования"""
        self.ui.stackedWidget.setCurrentIndex(2)
    
    def select_directory(self):
        """Открывает диалог выбора директории для сохранения ключей"""
        directory = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            "Select directory to save keys",
            "",
            QtWidgets.QFileDialog.ShowDirsOnly
        )
        if directory:
            self.ui.lineEdit_path.setText(directory)
            self.update_status_key_generation("Waiting for information...", None, None)
    
    def get_selected_key_size(self):
        """
        Определяет выбранный пользователем размер ключа
        
        Returns:
            int: Размер ключа в байтах (8, 16 или 24) или None, если ничего не выбрано
        """
        if self.ui.radioButton_64bit.isChecked():
            return 8
        elif self.ui.radioButton_128bit.isChecked():
            return 16
        elif self.ui.radioButton_192bit.isChecked():
            return 24
        else:
            return None
    
    def generate_keys(self):
        """Генерирует асимметричные (RSA) и симметричные ключи и сохраняет их в выбранную директорию"""
        self.ui.textEdit.clear()
        
        save_path = self.ui.lineEdit_path.text()
        if not save_path:
            self.update_status_key_generation("Error: No save directory selected!", None, None)
            return
        
        if not os.path.exists(save_path):
            self.update_status_key_generation("Error: Selected directory does not exist!", None, None)
            return
        
        if not save_path.endswith(os.sep):
            save_path += os.sep
        
        key_size_bytes = self.get_selected_key_size()
        if key_size_bytes is None:
            self.update_status_key_generation(
                "Error: No key size selected! Please choose 64, 128, or 192 bits.",
                None, None
            )
            return
        
        try:
            self.update_status_key_generation("Generating RSA keys...", key_size_bytes, None)
            QtWidgets.QApplication.processEvents()
            
            private_key, public_key = genAssimKey(save_path)
            
            self.update_status_key_generation("Generating symmetric key...", key_size_bytes, None)
            QtWidgets.QApplication.processEvents()
            
            symmetric_key, encrypted_symmetric_key = genSimKey(
                save_path + "symmetric_key",
                key_size_bytes,
                public_key
            )
            
            files_list = [
                f"{save_path}public.pem",
                f"{save_path}private.pem",
                f"{save_path}symmetric_key_encrypted_sym.key"
            ]
            
            self.update_status_key_generation("Success", key_size_bytes, files_list)
            
        except Exception as e:
            error_message = f"Error during key generation: {str(e)}"
            self.update_status_key_generation(error_message, None, None)
    
    def update_status_key_generation(self, status, key_size_bytes, files_list):
        """
        Обновляет статус на странице генерации ключей
        
        Args:
            status (str): Текст статуса
            key_size_bytes (int): Размер ключа в байтах
            files_list (list): Список путей к сгенерированным файлам
        """
        status_text = f"Status: {status}\n"
        
        if key_size_bytes is not None:
            status_text += f"Key size: {key_size_bytes * 8} bits ({key_size_bytes} bytes)\n"
        else:
            status_text += "Key size: -\n"
        
        if files_list is not None and len(files_list) > 0:
            for file_path in files_list:
                status_text += f"{file_path}\n"
        else:
            status_text += "-\n-\n"
        
        self.ui.textEdit.clear()
        self.ui.textEdit.append(status_text)
    
    def select_source_file(self):
        """Выбирает исходный текстовый файл (.txt) для шифрования"""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select source text file",
            "",
            "Text files (*.txt);;All files (*.*)"
        )
        if file_path:
            if not file_path.lower().endswith('.txt'):
                self.update_status_encryption("Error: Source file must be a .txt file!", None, None, None, None)
                return
            self.ui.lineEdit_path_source_file.setText(file_path)
            self.update_status_encryption("Waiting for information...", None, None, None, None)
    
    def select_private_key_file(self):
        """Выбирает файл приватного ключа (.pem) для шифрования"""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select private key file (.pem)",
            "",
            "PEM files (*.pem);;All files (*.*)"
        )
        if file_path:
            if not file_path.lower().endswith('.pem'):
                self.update_status_encryption("Error: Private key must be a .pem file!", None, None, None, None)
                return
            self.ui.lineEdit_path_4.setText(file_path)
            self.update_status_encryption("Waiting for information...", None, None, None, None)
    
    def select_sym_key_file(self):
        """Выбирает файл зашифрованного симметричного ключа (.txt) для шифрования"""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select encrypted symmetric key file (.txt)",
            "",
            "Text files (*.txt);;All files (*.*)"
        )
        if file_path:
            if not file_path.lower().endswith('.txt'):
                self.update_status_encryption("Error: Encrypted symmetric key must be a .txt file!", None, None, None, None)
                return
            self.ui.lineEdit_path_syn_key.setText(file_path)
            self.update_status_encryption("Waiting for information...", None, None, None, None)
    
    def select_result_directory(self):
        """Выбирает директорию для сохранения зашифрованного файла"""
        directory = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            "Select directory to save encrypted file",
            "",
            QtWidgets.QFileDialog.ShowDirsOnly
        )
        if directory:
            self.ui.lineEdit_path_result.setText(directory)
            self.update_status_encryption("Waiting for information...", None, None, None, None)
    
    def encrypt_file(self):
        """Выполняет шифрование выбранного файла с использованием RSA и 3DES"""
        self.ui.textEdit_status.clear()
        
        source_file = self.ui.lineEdit_path_source_file.text()
        private_key_path = self.ui.lineEdit_path_4.text()
        encrypted_sym_key_path = self.ui.lineEdit_path_syn_key.text()
        output_dir = self.ui.lineEdit_path_result.text()
        
        if not source_file:
            self.update_status_encryption("Error: Source file not selected!", None, None, None, None)
            return
        
        if not private_key_path:
            self.update_status_encryption("Error: Private key file not selected!", None, None, None, None)
            return
        
        if not encrypted_sym_key_path:
            self.update_status_encryption("Error: Encrypted symmetric key file not selected!", None, None, None, None)
            return
        
        if not output_dir:
            self.update_status_encryption("Error: Output directory not selected!", None, None, None, None)
            return
        
        if not os.path.exists(source_file):
            self.update_status_encryption(f"Error: Source file does not exist!\n{source_file}", None, None, None, None)
            return
        
        if not os.path.exists(private_key_path):
            self.update_status_encryption(f"Error: Private key file does not exist!\n{private_key_path}", None, None, None, None)
            return
        
        if not os.path.exists(encrypted_sym_key_path):
            self.update_status_encryption(f"Error: Encrypted symmetric key file does not exist!\n{encrypted_sym_key_path}", None, None, None, None)
            return
        
        if not os.path.exists(output_dir):
            self.update_status_encryption(f"Error: Output directory does not exist!\n{output_dir}", None, None, None, None)
            return
        
        try:
            with open(source_file, 'rb') as f:
                source_data = f.read()
            
            with open(encrypted_sym_key_path, 'rb') as f:
                encrypted_sym_key = f.read()
            
            with open(private_key_path, 'rb') as f:
                private_key_data = f.read()
            
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
            )
            
            base_name = os.path.basename(source_file)
            name_without_ext = os.path.splitext(base_name)[0]
            output_path = os.path.join(output_dir, f"{name_without_ext}_encrypted.bin")
            
            self.update_status_encryption("Encrypting file...", source_file, private_key_path, encrypted_sym_key_path, output_path)
            QtWidgets.QApplication.processEvents()
            
            encrypt_text_to_file(source_data, encrypted_sym_key, private_key, output_path)
            
            self.update_status_encryption("Success", source_file, private_key_path, encrypted_sym_key_path, output_path)
            
        except Exception as e:
            error_message = f"Error during encryption: {str(e)}"
            self.update_status_encryption(error_message, None, None, None, None)
    
    def update_status_encryption(self, status, source_file, private_key, sym_key, output_path):
        """
        Обновляет статус на странице шифрования
        
        Args:
            status (str): Текст статуса
            source_file (str): Путь к исходному файлу
            private_key (str): Путь к приватному ключу
            sym_key (str): Путь к зашифрованному симметричному ключу
            output_path (str): Путь для сохранения результата
        """
        status_text = f"Status: {status}\n"
        
        if source_file:
            status_text += f"Source file: {source_file}\n"
        else:
            status_text += "Source file: -\n"
        
        if private_key:
            status_text += f"Private key: {private_key}\n"
        else:
            status_text += "Private key: -\n"
        
        if sym_key:
            status_text += f"Encrypted symmetric key: {sym_key}\n"
        else:
            status_text += "Encrypted symmetric key: -\n"
        
        if output_path:
            status_text += f"Output: {output_path}"
        else:
            status_text += "Output: -"
        
        self.ui.textEdit_status.clear()
        self.ui.textEdit_status.append(status_text)
    
    def select_encrypted_file(self):
        """Выбирает зашифрованный файл (.bin) для дешифрования"""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select encrypted file (.bin)",
            "",
            "Binary files (*.bin);;All files (*.*)"
        )
        if file_path:
            if not file_path.lower().endswith('.bin'):
                self.update_status_decryption("Error: Encrypted file must be a .bin file!", None, None, None, None)
                return
            self.ui.lineEdit_path_encrypte_file.setText(file_path)
            self.update_status_decryption("Waiting for information...", None, None, None, None)
    
    def select_private_key_file_decrypt(self):
        """Выбирает файл приватного ключа (.pem) для дешифрования"""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select private key file (.pem)",
            "",
            "PEM files (*.pem);;All files (*.*)"
        )
        if file_path:
            if not file_path.lower().endswith('.pem'):
                self.update_status_decryption("Error: Private key must be a .pem file!", None, None, None, None)
                return
            self.ui.lineEdit_path_private_key.setText(file_path)
            self.update_status_decryption("Waiting for information...", None, None, None, None)
    
    def select_sym_key_file_decrypt(self):
        """Выбирает файл зашифрованного симметричного ключа (.txt) для дешифрования"""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select encrypted symmetric key file (.txt)",
            "",
            "Text files (*.txt);;All files (*.*)"
        )
        if file_path:
            if not file_path.lower().endswith('.txt'):
                self.update_status_decryption("Error: Encrypted symmetric key must be a .txt file!", None, None, None, None)
                return
            self.ui.lineEdit_path_sym_key.setText(file_path)
            self.update_status_decryption("Waiting for information...", None, None, None, None)
    
    def select_result_directory_decrypt(self):
        """Выбирает директорию для сохранения расшифрованного файла"""
        directory = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            "Select directory to save decrypted file",
            "",
            QtWidgets.QFileDialog.ShowDirsOnly
        )
        if directory:
            self.ui.lineEdit_path_result_2.setText(directory)
            self.update_status_decryption("Waiting for information...", None, None, None, None)
    
    def decrypt_file(self):
        """Выполняет дешифрование файла"""
        self.ui.textEdit_3.clear()
        
        encrypted_file = self.ui.lineEdit_path_encrypte_file.text()
        private_key_path = self.ui.lineEdit_path_private_key.text()
        encrypted_sym_key_path = self.ui.lineEdit_path_sym_key.text()
        output_dir = self.ui.lineEdit_path_result_2.text()
        
        if not encrypted_file:
            self.update_status_decryption("Error: Encrypted file not selected!", None, None, None, None)
            return
        
        if not private_key_path:
            self.update_status_decryption("Error: Private key file not selected!", None, None, None, None)
            return
        
        if not encrypted_sym_key_path:
            self.update_status_decryption("Error: Encrypted symmetric key file not selected!", None, None, None, None)
            return
        
        if not output_dir:
            self.update_status_decryption("Error: Output directory not selected!", None, None, None, None)
            return
        
        if not os.path.exists(encrypted_file):
            self.update_status_decryption(f"Error: Encrypted file does not exist!\n{encrypted_file}", None, None, None, None)
            return
        
        if not os.path.exists(private_key_path):
            self.update_status_decryption(f"Error: Private key file does not exist!\n{private_key_path}", None, None, None, None)
            return
        
        if not os.path.exists(encrypted_sym_key_path):
            self.update_status_decryption(f"Error: Encrypted symmetric key file does not exist!\n{encrypted_sym_key_path}", None, None, None, None)
            return
        
        if not os.path.exists(output_dir):
            self.update_status_decryption(f"Error: Output directory does not exist!\n{output_dir}", None, None, None, None)
            return
        
        try:
            with open(encrypted_sym_key_path, 'rb') as f:
                encrypted_sym_key = f.read()
            
            with open(private_key_path, 'rb') as f:
                private_key_data = f.read()
            
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
            )
            
            base_name = os.path.basename(encrypted_file)
            name_without_ext = os.path.splitext(base_name)[0]
            if name_without_ext.endswith('_encrypted'):
                name_without_ext = name_without_ext[:-10]
            output_path = os.path.join(output_dir, f"{name_without_ext}_decrypted.txt")
            
            self.update_status_decryption("Decrypting file...", encrypted_file, private_key_path, encrypted_sym_key_path, output_path)
            QtWidgets.QApplication.processEvents()
            
            decrypted_data = decrypt_text_from_file(encrypted_file, encrypted_sym_key, private_key)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.update_status_decryption("Success", encrypted_file, private_key_path, encrypted_sym_key_path, output_path)
            
        except Exception as e:
            error_message = f"Error during decryption: {str(e)}"
            self.update_status_decryption(error_message, None, None, None, None)
    
    def update_status_decryption(self, status, encrypted_file, private_key, sym_key, output_path):
        """
        Обновляет статус на странице дешифрования
        
        Args:
            status (str): Текст статуса
            encrypted_file (str): Путь к зашифрованному файлу
            private_key (str): Путь к приватному ключу
            sym_key (str): Путь к зашифрованному симметричному ключу
            output_path (str): Путь для сохранения результата
        """
        status_text = f"Status: {status}\n"
        
        if encrypted_file:
            status_text += f"Encrypted file: {encrypted_file}\n"
        else:
            status_text += "Encrypted file: -\n"
        
        if private_key:
            status_text += f"Private key: {private_key}\n"
        else:
            status_text += "Private key: -\n"
        
        if sym_key:
            status_text += f"Encrypted symmetric key: {sym_key}\n"
        else:
            status_text += "Encrypted symmetric key: -\n"
        
        if output_path:
            status_text += f"Output: {output_path}"
        else:
            status_text += "Output: -"
        
        self.ui.textEdit_3.clear()
        self.ui.textEdit_3.append(status_text)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    myapp = MyWin()
    myapp.show()
    sys.exit(app.exec_())