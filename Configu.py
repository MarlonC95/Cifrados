"""
Configuración de la aplicación de criptografía
"""

import os
import json
from datetime import datetime

class Config:
    def __init__(self):
        self.app_name = "Sistema de Criptografía Asimétrica"
        self.version = "2.0"
        self.author = "Tu Nombre"
        
        # Configuración de carpetas
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.keys_folder = os.path.join(self.base_dir, "keys_storage")
        self.backup_folder = os.path.join(self.keys_folder, "backup")
        self.export_folder = os.path.join(self.keys_folder, "exported")
        
        # Configuración de algoritmos
        self.supported_algorithms = {
            "RSA": {"key_sizes": [2048, 3072, 4096], "default_size": 2048},
            "ECC": {"curves": ["P-256", "P-384", "P-521"], "default_curve": "P-256"}
        }
        
        # Configuración de seguridad
        self.default_hash = "SHA256"
        self.default_padding = "OAEP"
        
    def get_folder_structure(self):
        """Obtener la estructura de carpetas"""
        return {
            "keys_storage": {
                "rsa": "Almacenamiento de claves RSA",
                "ecc": "Almacenamiento de claves ECC", 
                "backup": "Copias de seguridad de claves",
                "exported": "Claves exportadas"
            }
        }
    
    def create_default_config(self):
        """Crear archivo de configuración por defecto"""
        config_data = {
            "app_info": {
                "name": self.app_name,
                "version": self.version,
                "last_launch": datetime.now().isoformat()
            },
            "paths": {
                "keys_folder": self.keys_folder,
                "backup_folder": self.backup_folder
            },
            "security": {
                "default_algorithm": "RSA",
                "default_key_size": 2048,
                "auto_save_keys": True,
                "auto_backup": True
            }
        }
        
        config_path = os.path.join(self.base_dir, "app_config.json")
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        return config_path