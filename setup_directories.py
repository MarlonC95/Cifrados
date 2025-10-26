#!/usr/bin/env python3
"""
Script de inicialización para crear la estructura de carpetas
"""

import os
from Configu import Config

def setup_environment():
    """Configurar el entorno de la aplicación"""
    print("🔧 Configurando entorno de criptografía...")
    
    config = Config()
    
    # Crear estructura de carpetas
    folders_to_create = [
        config.keys_folder,
        os.path.join(config.keys_folder, "rsa"),
        os.path.join(config.keys_folder, "ecc"), 
        os.path.join(config.keys_folder, "backup"),
        os.path.join(config.keys_folder, "exported")
    ]
    
    for folder in folders_to_create:
        try:
            os.makedirs(folder, exist_ok=True)
            print(f"✓ Carpeta creada: {folder}")
        except Exception as e:
            print(f"✗ Error creando {folder}: {e}")
    
    # Crear archivo de configuración
    try:
        config_path = config.create_default_config()
        print(f"✓ Configuración creada: {config_path}")
    except Exception as e:
        print(f"✗ Error creando configuración: {e}")
    
    # Crear archivo README en la carpeta de llaves
    readme_path = os.path.join(config.keys_folder, "README.txt")
    readme_content = """📁 CARPETA DE ALMACENAMIENTO DE LLAVES

Esta carpeta contiene todas las llaves criptográficas generadas por la aplicación.

ESTRUCTURA:
├── rsa/          - Llaves RSA
├── ecc/          - Llaves ECC  
├── backup/       - Copias de seguridad
└── exported/     - Llaves exportadas

ARCHIVOS:
• _private.pem   - Llaves privadas (MANTENER SEGURAS)
• _public.pem    - Llaves públicas (pueden compartirse)
• keys_index.json - Índice de todas las llaves

SEGURIDAD:
• Las llaves privadas deben protegerse con contraseña
• Realizar backups regularmente
• No compartir llaves privadas
"""
    
    try:
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(readme_content)
        print(f"✓ README creado: {readme_path}")
    except Exception as e:
        print(f"✗ Error creando README: {e}")
    
    print("\n🎉 Configuración completada!")
    print(f"📁 Carpeta de llaves: {config.keys_folder}")
    
    return True

if __name__ == "__main__":
    setup_environment()