import customtkinter as ctk
from tkinter import filedialog, messagebox, scrolledtext
import os
import time
import threading
from datetime import datetime
import json
import shutil
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import base64
import secrets

# Configuración de customtkinter
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Sistema Avanzado de Criptografía Asimétrica")
        self.geometry("1200x800")
        self.resizable(True, True)
        
        # Configurar carpeta de llaves
        self.keys_folder = "keys_storage"
        self.setup_keys_folder()
        
        # Variables para almacenar claves
        self.private_key = None
        self.public_key = None
        self.key_pairs = {}  # Diccionario para múltiples pares de claves
        self.current_key_name = None
        self.operation_log = []
        
        # Crear pestañas
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Crear las pestañas
        self.tab_keys = self.tabview.add("🔑 Gestión de Claves")
        self.tab_encrypt = self.tabview.add("🔒 Cifrar/Descifrar")
        self.tab_sign = self.tabview.add("📝 Firmar/Verificar")
        self.tab_animation = self.tabview.add("🎬 Animación Criptográfica")
        self.tab_logs = self.tabview.add("📊 Registros y Estadísticas")
        
        # Configurar cada pestaña
        self.setup_keys_tab()
        self.setup_encrypt_tab()
        self.setup_sign_tab()
        self.setup_animation_tab()
        self.setup_logs_tab()
        
        # Cargar claves existentes al iniciar
        self.load_existing_keys()
        
        # Inicializar log
        self.log_operation("Aplicación iniciada")
        
    def setup_keys_folder(self):
        """Crear y configurar la carpeta de almacenamiento de llaves"""
        try:
            # Crear carpeta principal
            if not os.path.exists(self.keys_folder):
                os.makedirs(self.keys_folder)
                print(f"✓ Carpeta de llaves creada: {self.keys_folder}")
            
            # Crear subcarpetas organizadas
            subfolders = ['rsa', 'ecc', 'backup', 'exported']
            for folder in subfolders:
                folder_path = os.path.join(self.keys_folder, folder)
                if not os.path.exists(folder_path):
                    os.makedirs(folder_path)
            
            # Crear archivo de índice de claves
            self.keys_index_file = os.path.join(self.keys_folder, "keys_index.json")
            if not os.path.exists(self.keys_index_file):
                with open(self.keys_index_file, 'w') as f:
                    json.dump({}, f, indent=2)
                    
            print("✓ Estructura de carpetas de llaves configurada correctamente")
            
        except Exception as e:
            print(f"✗ Error al configurar carpeta de llaves: {e}")
            messagebox.showerror("Error", f"No se pudo crear la carpeta de llaves: {e}")
    
    def load_existing_keys(self):
        """Cargar claves existentes de la carpeta al iniciar la aplicación"""
        try:
            if os.path.exists(self.keys_index_file):
                with open(self.keys_index_file, 'r') as f:
                    keys_index = json.load(f)
                
                loaded_count = 0
                for key_name, key_info in keys_index.items():
                    try:
                        # Cargar clave privada si existe
                        priv_key_path = key_info.get('private_key_path')
                        if priv_key_path and os.path.exists(priv_key_path):
                            with open(priv_key_path, 'rb') as f:
                                private_key = serialization.load_pem_private_key(
                                    f.read(),
                                    password=None
                                )
                            
                            self.key_pairs[key_name] = {
                                'private_key': private_key,
                                'public_key': private_key.public_key(),
                                'algorithm': key_info.get('algorithm', 'RSA'),
                                'created': key_info.get('created', 'Desconocida'),
                                'file_paths': key_info
                            }
                            loaded_count += 1
                            
                        # Cargar solo clave pública si no hay privada
                        elif key_info.get('public_key_path') and os.path.exists(key_info['public_key_path']):
                            with open(key_info['public_key_path'], 'rb') as f:
                                public_key = serialization.load_pem_public_key(f.read())
                            
                            self.key_pairs[key_name] = {
                                'private_key': None,
                                'public_key': public_key,
                                'algorithm': key_info.get('algorithm', 'RSA'),
                                'created': key_info.get('created', 'Desconocida'),
                                'file_paths': key_info
                            }
                            loaded_count += 1
                            
                    except Exception as e:
                        print(f"✗ Error cargando clave {key_name}: {e}")
                        continue
                
                if loaded_count > 0:
                    self.update_key_selector()
                    self.log_operation(f"Cargadas {loaded_count} claves existentes al iniciar")
                    
        except Exception as e:
            print(f"✗ Error cargando índice de claves: {e}")
    
    def save_key_to_index(self, key_name, key_data, priv_path=None, pub_path=None):
        """Guardar información de la clave en el índice"""
        try:
            with open(self.keys_index_file, 'r') as f:
                keys_index = json.load(f)
            
            keys_index[key_name] = {
                'algorithm': key_data['algorithm'],
                'created': key_data['created'],
                'private_key_path': priv_path,
                'public_key_path': pub_path,
                'last_used': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            with open(self.keys_index_file, 'w') as f:
                json.dump(keys_index, f, indent=2)
                
        except Exception as e:
            print(f"✗ Error guardando en índice: {e}")
    
    def setup_keys_tab(self):
        """Configurar la pestaña de gestión de claves"""
        # Título
        title_label = ctk.CTkLabel(self.tab_keys, text="Gestión Avanzada de Claves", 
                                  font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=10)
        
        # Información de carpeta
        folder_info = ctk.CTkLabel(self.tab_keys, 
                                  text=f"📁 Carpeta de llaves: {os.path.abspath(self.keys_folder)}",
                                  text_color="lightblue")
        folder_info.pack(pady=5)
        
        # Frame para selección de algoritmo
        algo_frame = ctk.CTkFrame(self.tab_keys)
        algo_frame.pack(fill="x", padx=20, pady=10)
        
        algo_label = ctk.CTkLabel(algo_frame, text="Seleccionar Algoritmo:", 
                                 font=ctk.CTkFont(size=14, weight="bold"))
        algo_label.pack(pady=5)
        
        self.algo_var = ctk.StringVar(value="RSA")
        rsa_radio = ctk.CTkRadioButton(algo_frame, text="RSA 2048 bits", 
                                      variable=self.algo_var, value="RSA")
        rsa_radio.pack(side="left", padx=10)
        
        ecc_radio = ctk.CTkRadioButton(algo_frame, text="ECC P-256", 
                                      variable=self.algo_var, value="ECC")
        ecc_radio.pack(side="left", padx=10)
        
        # Frame para generar claves
        gen_frame = ctk.CTkFrame(self.tab_keys)
        gen_frame.pack(fill="x", padx=20, pady=10)
        
        gen_label = ctk.CTkLabel(gen_frame, text="Generar Nuevas Claves", 
                                font=ctk.CTkFont(size=16, weight="bold"))
        gen_label.pack(pady=10)
        
        # Entrada para nombre de clave
        name_frame = ctk.CTkFrame(gen_frame)
        name_frame.pack(fill="x", padx=20, pady=5)
        
        name_label = ctk.CTkLabel(name_frame, text="Nombre del par:")
        name_label.pack(side="left", padx=5)
        
        self.key_name_entry = ctk.CTkEntry(name_frame, placeholder_text="ej: mi_clave_principal")
        self.key_name_entry.pack(side="left", fill="x", expand=True, padx=5)
        
        # Botón para generar claves
        gen_button = ctk.CTkButton(gen_frame, text="Generar Par de Claves", 
                                  command=self.generate_keys)
        gen_button.pack(pady=10)
        
        # Frame para gestión múltiple de claves
        multi_key_frame = ctk.CTkFrame(self.tab_keys)
        multi_key_frame.pack(fill="x", padx=20, pady=10)
        
        multi_label = ctk.CTkLabel(multi_key_frame, text="Gestión de Múltiples Claves", 
                                  font=ctk.CTkFont(size=16, weight="bold"))
        multi_label.pack(pady=10)
        
        # Selección de clave actual
        select_frame = ctk.CTkFrame(multi_key_frame)
        select_frame.pack(fill="x", padx=20, pady=5)
        
        select_label = ctk.CTkLabel(select_frame, text="Clave actual:")
        select_label.pack(side="left", padx=5)
        
        self.key_selector = ctk.CTkComboBox(select_frame, values=[], 
                                           command=self.select_key_pair)
        self.key_selector.pack(side="left", fill="x", expand=True, padx=5)
        
        # Botón para abrir carpeta de llaves
        open_folder_btn = ctk.CTkButton(select_frame, text="📁 Abrir Carpeta",
                                       command=self.open_keys_folder, width=120)
        open_folder_btn.pack(side="left", padx=5)
        
        # Frame para acciones de claves
        actions_frame = ctk.CTkFrame(multi_key_frame)
        actions_frame.pack(fill="x", padx=20, pady=10)
        
        # Botones para guardar claves automáticamente
        auto_save_label = ctk.CTkLabel(actions_frame, text="Guardado Automático:",
                                      font=ctk.CTkFont(weight="bold"))
        auto_save_label.pack(pady=5)
        
        auto_buttons_frame = ctk.CTkFrame(actions_frame)
        auto_buttons_frame.pack(pady=5)
        
        save_auto_btn = ctk.CTkButton(auto_buttons_frame, text="💾 Guardar Clave Actual",
                                     command=self.save_current_key_auto)
        save_auto_btn.pack(side="left", padx=5)
        
        save_all_btn = ctk.CTkButton(auto_buttons_frame, text="💾 Guardar Todas las Claves",
                                    command=self.save_all_keys_auto)
        save_all_btn.pack(side="left", padx=5)
        
        # Botones para gestión manual
        manual_frame = ctk.CTkFrame(self.tab_keys)
        manual_frame.pack(fill="x", padx=20, pady=10)
        
        manual_label = ctk.CTkLabel(manual_frame, text="Gestión Manual de Archivos:", 
                                   font=ctk.CTkFont(size=16, weight="bold"))
        manual_label.pack(pady=10)
        
        manual_buttons_frame = ctk.CTkFrame(manual_frame)
        manual_buttons_frame.pack(pady=10)
        
        save_private_btn = ctk.CTkButton(manual_buttons_frame, text="Guardar Clave Privada",
                                        command=self.save_private_key_manual)
        save_private_btn.pack(side="left", padx=5)
        
        save_public_btn = ctk.CTkButton(manual_buttons_frame, text="Guardar Clave Pública",
                                       command=self.save_public_key_manual)
        save_public_btn.pack(side="left", padx=5)
        
        load_private_btn = ctk.CTkButton(manual_buttons_frame, text="Cargar Clave Privada",
                                        command=self.load_private_key_manual)
        load_private_btn.pack(side="left", padx=5)
        
        load_public_btn = ctk.CTkButton(manual_buttons_frame, text="Cargar Clave Pública",
                                       command=self.load_public_key_manual)
        load_public_btn.pack(side="left", padx=5)
        
        # Botones adicionales
        extra_buttons_frame = ctk.CTkFrame(manual_frame)
        extra_buttons_frame.pack(pady=5)
        
        export_all_btn = ctk.CTkButton(extra_buttons_frame, text="📤 Exportar Todas",
                                      command=self.export_all_keys)
        export_all_btn.pack(side="left", padx=5)
        
        backup_btn = ctk.CTkButton(extra_buttons_frame, text="📦 Crear Backup",
                                  command=self.create_backup)
        backup_btn.pack(side="left", padx=5)
        
        refresh_btn = ctk.CTkButton(extra_buttons_frame, text="🔄 Recargar Claves",
                                   command=self.refresh_keys)
        refresh_btn.pack(side="left", padx=5)
        
        # Área de información
        self.keys_info = ctk.CTkTextbox(self.tab_keys, height=150)
        self.keys_info.pack(fill="x", padx=20, pady=10)
        self.keys_info.insert("1.0", "Información de claves aparecerá aquí...\n")
        self.keys_info.configure(state="disabled")
    
    def setup_encrypt_tab(self):
        """Configurar la pestaña de cifrado/descifrado"""
        # Título
        title_label = ctk.CTkLabel(self.tab_encrypt, text="Cifrado y Descifrado Avanzado", 
                                  font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=10)
        
        # Información de cifrado
        info_label = ctk.CTkLabel(self.tab_encrypt, 
                                 text="💡 Para textos largos se usa cifrado híbrido (RSA + AES)",
                                 text_color="lightblue")
        info_label.pack(pady=5)
        
        # Frame para modo de operación
        mode_frame = ctk.CTkFrame(self.tab_encrypt)
        mode_frame.pack(fill="x", padx=20, pady=10)
        
        mode_label = ctk.CTkLabel(mode_frame, text="Modo de Operación:")
        mode_label.pack(side="left", padx=5)
        
        self.encrypt_mode = ctk.StringVar(value="text")
        text_radio = ctk.CTkRadioButton(mode_frame, text="Texto", 
                                       variable=self.encrypt_mode, value="text")
        text_radio.pack(side="left", padx=10)
        
        file_radio = ctk.CTkRadioButton(mode_frame, text="Archivo", 
                                       variable=self.encrypt_mode, value="file")
        file_radio.pack(side="left", padx=10)
        
        # Frame para entrada de texto
        self.input_frame = ctk.CTkFrame(self.tab_encrypt)
        self.input_frame.pack(fill="x", padx=20, pady=10)
        
        input_label = ctk.CTkLabel(self.input_frame, text="Texto a Cifrar/Descifrar:")
        input_label.pack(anchor="w", pady=5)
        
        self.encrypt_text = scrolledtext.ScrolledText(self.input_frame, height=8)
        self.encrypt_text.pack(fill="x", pady=5)
        
        # Frame para información de archivo
        self.file_info_frame = ctk.CTkFrame(self.tab_encrypt)
        self.file_info_label = ctk.CTkLabel(self.file_info_frame, text="")
        self.file_info_label.pack(pady=5)
        
        # Botones para archivos
        file_buttons_frame = ctk.CTkFrame(self.input_frame)
        file_buttons_frame.pack(fill="x", pady=5)
        
        load_file_btn = ctk.CTkButton(file_buttons_frame, text="Cargar Archivo",
                                     command=self.load_file_for_encryption)
        load_file_btn.pack(side="left", padx=5)
        
        # Botones de operación
        op_buttons_frame = ctk.CTkFrame(self.tab_encrypt)
        op_buttons_frame.pack(fill="x", padx=20, pady=10)
        
        encrypt_btn = ctk.CTkButton(op_buttons_frame, text="🔒 Cifrar", 
                                   command=self.encrypt_text_func)
        encrypt_btn.pack(side="left", padx=5)
        
        decrypt_btn = ctk.CTkButton(op_buttons_frame, text="🔓 Descifrar", 
                                   command=self.decrypt_text_func)
        decrypt_btn.pack(side="left", padx=5)
        
        clear_btn = ctk.CTkButton(op_buttons_frame, text="🗑️ Limpiar", 
                                 command=self.clear_encrypt_text)
        clear_btn.pack(side="left", padx=5)
        
        # Frame para resultado
        result_frame = ctk.CTkFrame(self.tab_encrypt)
        result_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        result_label = ctk.CTkLabel(result_frame, text="Resultado:")
        result_label.pack(anchor="w", pady=5)
        
        self.encrypt_result = scrolledtext.ScrolledText(result_frame, height=8)
        self.encrypt_result.pack(fill="both", expand=True, pady=5)
        
        # Frame para guardar resultados
        save_results_frame = ctk.CTkFrame(self.tab_encrypt)
        save_results_frame.pack(fill="x", padx=20, pady=10)
        
        save_results_label = ctk.CTkLabel(save_results_frame, text="Guardar Resultados:",
                                        font=ctk.CTkFont(weight="bold"))
        save_results_label.pack(pady=5)
        
        save_buttons_frame = ctk.CTkFrame(save_results_frame)
        save_buttons_frame.pack(pady=5)
        
        save_encrypted_btn = ctk.CTkButton(save_buttons_frame, text="💾 Guardar Texto Cifrado",
                                          command=self.save_encrypted_complete)
        save_encrypted_btn.pack(side="left", padx=5)
        
        save_decrypted_btn = ctk.CTkButton(save_buttons_frame, text="💾 Guardar Texto Descifrado",
                                          command=self.save_decrypted_complete)
        save_decrypted_btn.pack(side="left", padx=5)
        
        save_both_btn = ctk.CTkButton(save_buttons_frame, text="💾 Guardar Ambos",
                                     command=self.save_both_results)
        save_both_btn.pack(side="left", padx=5)
        
        # Ocultar frame de archivo inicialmente
        self.file_info_frame.pack_forget()
    
    def setup_sign_tab(self):
        """Configurar la pestaña de firma digital"""
        # Título
        title_label = ctk.CTkLabel(self.tab_sign, text="Firma Digital Avanzada", 
                                  font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=10)
        
        # Frame para entrada
        input_frame = ctk.CTkFrame(self.tab_sign)
        input_frame.pack(fill="x", padx=20, pady=10)
        
        input_label = ctk.CTkLabel(input_frame, text="Texto o Mensaje:")
        input_label.pack(anchor="w", pady=5)
        
        self.sign_text = scrolledtext.ScrolledText(input_frame, height=6)
        self.sign_text.pack(fill="x", pady=5)
        
        # Botones para archivos
        file_buttons_frame = ctk.CTkFrame(input_frame)
        file_buttons_frame.pack(fill="x", pady=5)
        
        load_file_btn = ctk.CTkButton(file_buttons_frame, text="Cargar Archivo para Firmar",
                                     command=self.load_file_for_signing)
        load_file_btn.pack(side="left", padx=5)
        
        # Frame para firma
        sign_frame = ctk.CTkFrame(self.tab_sign)
        sign_frame.pack(fill="x", padx=20, pady=10)
        
        sign_label = ctk.CTkLabel(sign_frame, text="Firma Digital:")
        sign_label.pack(anchor="w", pady=5)
        
        self.signature_text = ctk.CTkTextbox(sign_frame, height=4)
        self.signature_text.pack(fill="x", pady=5)
        
        # Botones de operación
        op_buttons_frame = ctk.CTkFrame(self.tab_sign)
        op_buttons_frame.pack(fill="x", padx=20, pady=10)
        
        sign_btn = ctk.CTkButton(op_buttons_frame, text="✍️ Firmar Mensaje", 
                                command=self.sign_message)
        sign_btn.pack(side="left", padx=5)
        
        verify_btn = ctk.CTkButton(op_buttons_frame, text="🔍 Verificar Firma", 
                                  command=self.verify_signature)
        verify_btn.pack(side="left", padx=5)
        
        clear_btn = ctk.CTkButton(op_buttons_frame, text="🗑️ Limpiar", 
                                 command=self.clear_sign_text)
        clear_btn.pack(side="left", padx=5)
        
        # Resultado de verificación
        self.verify_result = ctk.CTkLabel(self.tab_sign, text="", 
                                         font=ctk.CTkFont(size=14, weight="bold"))
        self.verify_result.pack(pady=10)
        
    def setup_animation_tab(self):
        """Configurar la pestaña de animación criptográfica"""
        # Título
        title_label = ctk.CTkLabel(self.tab_animation, text="Animación del Proceso Criptográfico", 
                                  font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=10)
        
        # Frame de controles
        controls_frame = ctk.CTkFrame(self.tab_animation)
        controls_frame.pack(fill="x", padx=20, pady=10)
        
        # Entrada para texto a animar
        input_label = ctk.CTkLabel(controls_frame, text="Texto para animación:")
        input_label.pack(anchor="w", pady=5)
        
        self.animation_input = ctk.CTkTextbox(controls_frame, height=4)
        self.animation_input.pack(fill="x", pady=5)
        self.animation_input.insert("1.0", "Hola Mundo Criptográfico!")
        
        # Botones de animación
        anim_buttons_frame = ctk.CTkFrame(controls_frame)
        anim_buttons_frame.pack(fill="x", pady=10)
        
        encrypt_anim_btn = ctk.CTkButton(anim_buttons_frame, text="🎬 Animar Cifrado",
                                        command=self.start_encryption_animation)
        encrypt_anim_btn.pack(side="left", padx=5)
        
        decrypt_anim_btn = ctk.CTkButton(anim_buttons_frame, text="🎬 Animar Descifrado",
                                        command=self.start_decryption_animation)
        decrypt_anim_btn.pack(side="left", padx=5)
        
        clear_anim_btn = ctk.CTkButton(anim_buttons_frame, text="🗑️ Limpiar Animación",
                                      command=self.clear_animation)
        clear_anim_btn.pack(side="left", padx=5)
        
        # Frame para visualización
        self.animation_frame = ctk.CTkFrame(self.tab_animation)
        self.animation_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Área de texto para mostrar el proceso paso a paso
        self.animation_display = scrolledtext.ScrolledText(self.animation_frame, height=15)
        self.animation_display.pack(fill="both", expand=True)
        self.animation_display.insert("1.0", "La animación del proceso criptográfico aparecerá aquí...\n\n")
        self.animation_display.configure(state="disabled")
        
        # Progress bar
        self.animation_progress = ctk.CTkProgressBar(self.animation_frame)
        self.animation_progress.pack(fill="x", pady=10)
        self.animation_progress.set(0)
        
        # Label de progreso
        self.animation_status = ctk.CTkLabel(self.animation_frame, text="Listo para animar...")
        self.animation_status.pack(pady=5)
        
    def setup_logs_tab(self):
        """Configurar la pestaña de registros y estadísticas"""
        # Título
        title_label = ctk.CTkLabel(self.tab_logs, text="Registros y Estadísticas", 
                                  font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=10)
        
        # Frame para controles de log
        log_controls_frame = ctk.CTkFrame(self.tab_logs)
        log_controls_frame.pack(fill="x", padx=20, pady=10)
        
        # Botones de gestión de logs
        clear_logs_btn = ctk.CTkButton(log_controls_frame, text="🗑️ Limpiar Registros",
                                      command=self.clear_logs)
        clear_logs_btn.pack(side="left", padx=5)
        
        export_logs_btn = ctk.CTkButton(log_controls_frame, text="📤 Exportar Logs",
                                       command=self.export_logs)
        export_logs_btn.pack(side="left", padx=5)
        
        stats_btn = ctk.CTkButton(log_controls_frame, text="📊 Generar Estadísticas",
                                 command=self.generate_statistics)
        stats_btn.pack(side="left", padx=5)
        
        # Frame para logs
        logs_frame = ctk.CTkFrame(self.tab_logs)
        logs_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Área de logs
        self.logs_display = scrolledtext.ScrolledText(logs_frame, height=15)
        self.logs_display.pack(fill="both", expand=True)
        
        # Frame para estadísticas
        stats_frame = ctk.CTkFrame(self.tab_logs)
        stats_frame.pack(fill="x", padx=20, pady=10)
        
        stats_label = ctk.CTkLabel(stats_frame, text="Estadísticas:", 
                                  font=ctk.CTkFont(size=14, weight="bold"))
        stats_label.pack(anchor="w", pady=5)
        
        self.stats_display = ctk.CTkTextbox(stats_frame, height=6)
        self.stats_display.pack(fill="x", pady=5)
        self.stats_display.insert("1.0", "Las estadísticas aparecerán aquí...")
        self.stats_display.configure(state="disabled")
    
    # ========== MÉTODOS DE CIFRADO HÍBRIDO ==========
    
    def encrypt_rsa_aes_hybrid(self, plaintext):
        """Cifrado híbrido RSA + AES para textos largos"""
        try:
            # Generar una clave AES aleatoria
            aes_key = secrets.token_bytes(32)  # 256 bits
            iv = secrets.token_bytes(16)       # Vector de inicialización
            
            # Cifrar la clave AES con RSA
            encrypted_aes_key = self.public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Cifrar el texto con AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Aplicar padding al texto
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            
            # Cifrar los datos
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combinar todo en un formato estructurado
            hybrid_data = {
                'version': '1.0',
                'algorithm': 'RSA-AES-HYBRID',
                'encrypted_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'timestamp': datetime.now().isoformat()
            }
            
            return json.dumps(hybrid_data)
            
        except Exception as e:
            raise Exception(f"Error en cifrado híbrido: {str(e)}")
    
    def decrypt_rsa_aes_hybrid(self, encrypted_data_str):
        """Descifrado híbrido RSA + AES"""
        try:
            # Parsear los datos
            hybrid_data = json.loads(encrypted_data_str)
            
            # Extraer componentes
            encrypted_aes_key = base64.b64decode(hybrid_data['encrypted_key'])
            iv = base64.b64decode(hybrid_data['iv'])
            ciphertext = base64.b64decode(hybrid_data['ciphertext'])
            
            # Descifrar la clave AES con RSA
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Descifrar el texto con AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            # Descifrar datos
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remover padding
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext
            
        except Exception as e:
            raise Exception(f"Error en descifrado híbrido: {str(e)}")
    
    def encrypt_simple_rsa(self, plaintext):
        """Cifrado RSA simple para textos cortos"""
        try:
            ciphertext = self.public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return base64.b64encode(ciphertext).decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Error en cifrado RSA simple: {str(e)}")
    
    def decrypt_simple_rsa(self, ciphertext_b64):
        """Descifrado RSA simple para textos cortos"""
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            
            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return plaintext
            
        except Exception as e:
            raise Exception(f"Error en descifrado RSA simple: {str(e)}")
    
    # ========== MÉTODOS PRINCIPALES DE CIFRADO/DESCIFRADO ==========
    
    def encrypt_text_func(self):
        """Cifrar texto/archivo usando el método apropiado"""
        if self.public_key is None:
            messagebox.showwarning("Advertencia", "Debe cargar una clave pública primero")
            return
            
        try:
            content = self.encrypt_text.get('1.0', 'end-1c')
            
            # Determinar si es texto plano o archivo binario
            if content.startswith("[Archivo binario"):
                # Extraer datos binarios de base64
                lines = content.split('\n')
                base64_data = lines[2] if len(lines) > 2 else ""
                plaintext = base64.b64decode(base64_data)
            else:
                plaintext = content.encode('utf-8')
            
            if not plaintext:
                messagebox.showwarning("Advertencia", "No hay contenido para cifrar")
                return
            
            # Elegir método de cifrado basado en la longitud
            if len(plaintext) <= 190:  # Límite para RSA directo
                encrypted_data = self.encrypt_simple_rsa(plaintext)
                method_used = "RSA Directo"
            else:
                encrypted_data = self.encrypt_rsa_aes_hybrid(plaintext)
                method_used = "Híbrido RSA+AES"
            
            # Mostrar resultado
            self.encrypt_result.delete('1.0', 'end')
            self.encrypt_result.insert('1.0', f"Método usado: {method_used}\n")
            self.encrypt_result.insert('end', f"Tamaño original: {len(plaintext)} bytes\n")
            self.encrypt_result.insert('end', f"Tamaño cifrado: {len(encrypted_data)} bytes\n")
            self.encrypt_result.insert('end', "=" * 50 + "\n")
            self.encrypt_result.insert('end', encrypted_data)
            
            self.log_operation(f"Texto cifrado usando {method_used} - {len(plaintext)} bytes")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al cifrar: {str(e)}")
    
    def decrypt_text_func(self):
        """Descifrar texto usando el método apropiado"""
        if self.private_key is None:
            messagebox.showwarning("Advertencia", "Debe cargar una clave privada primero")
            return
            
        try:
            encrypted_data = self.encrypt_text.get('1.0', 'end-1c').strip()
            if not encrypted_data:
                messagebox.showwarning("Advertencia", "No hay texto cifrado para descifrar")
                return
            
            # Determinar el método de cifrado usado
            if encrypted_data.startswith('{'):  # Formato JSON = cifrado híbrido
                plaintext = self.decrypt_rsa_aes_hybrid(encrypted_data)
                method_used = "Híbrido RSA+AES"
            else:  # Base64 simple = cifrado RSA directo
                plaintext = self.decrypt_simple_rsa(encrypted_data)
                method_used = "RSA Directo"
            
            # Mostrar resultado
            self.encrypt_result.delete('1.0', 'end')
            self.encrypt_result.insert('1.0', f"Método usado: {method_used}\n")
            self.encrypt_result.insert('end', f"Tamaño descifrado: {len(plaintext)} bytes\n")
            self.encrypt_result.insert('end', "=" * 50 + "\n")
            
            # Intentar decodificar como texto, sino mostrar como binario
            try:
                decoded_text = plaintext.decode('utf-8')
                self.encrypt_result.insert('end', decoded_text)
            except UnicodeDecodeError:
                self.encrypt_result.insert('end', f"[Contenido binario descifrado - {len(plaintext)} bytes]\n")
                self.encrypt_result.insert('end', f"Base64: {base64.b64encode(plaintext).decode('utf-8')}")
            
            self.log_operation(f"Texto descifrado usando {method_used} - {len(plaintext)} bytes")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al descifrar: {str(e)}")
    
    # ========== MÉTODOS PARA GUARDAR RESULTADOS COMPLETOS ==========
    
    def save_encrypted_complete(self):
        """Guardar texto cifrado completo en archivo"""
        try:
            encrypted_content = self.encrypt_result.get('1.0', 'end-1c')
            if not encrypted_content.strip():
                messagebox.showwarning("Advertencia", "No hay texto cifrado para guardar")
                return
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".enc",
                filetypes=[
                    ("Archivos cifrados", "*.enc"),
                    ("Archivos JSON", "*.json"),
                    ("Todos los archivos", "*.*")
                ],
                title="Guardar texto cifrado completo"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(encrypted_content)
                
                messagebox.showinfo("Éxito", f"Texto cifrado guardado en:\n{filename}")
                self.log_operation(f"Texto cifrado guardado: {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar texto cifrado: {str(e)}")
    
    def save_decrypted_complete(self):
        """Guardar texto descifrado completo en archivo"""
        try:
            decrypted_content = self.encrypt_result.get('1.0', 'end-1c')
            if not decrypted_content.strip():
                messagebox.showwarning("Advertencia", "No hay texto descifrado para guardar")
                return
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[
                    ("Archivos de texto", "*.txt"),
                    ("Todos los archivos", "*.*")
                ],
                title="Guardar texto descifrado completo"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(decrypted_content)
                
                messagebox.showinfo("Éxito", f"Texto descifrado guardado en:\n{filename}")
                self.log_operation(f"Texto descifrado guardado: {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar texto descifrado: {str(e)}")
    
    def save_both_results(self):
        """Guardar tanto el texto cifrado como el descifrado"""
        try:
            # Obtener contenido actual del resultado
            result_content = self.encrypt_result.get('1.0', 'end-1c')
            if not result_content.strip():
                messagebox.showwarning("Advertencia", "No hay resultados para guardar")
                return
            
            # Crear carpeta para los resultados
            results_dir = "resultados_criptografia"
            if not os.path.exists(results_dir):
                os.makedirs(results_dir)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Guardar resultado completo
            result_filename = os.path.join(results_dir, f"resultado_completo_{timestamp}.txt")
            with open(result_filename, 'w', encoding='utf-8') as f:
                f.write("=== RESULTADO DE OPERACIÓN CRIPTOGRÁFICA ===\n")
                f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 50 + "\n\n")
                f.write(result_content)
            
            # Si el resultado contiene texto cifrado, guardarlo por separado
            if "Método usado:" in result_content and "Texto cifrado" not in result_content:
                lines = result_content.split('\n')
                for i, line in enumerate(lines):
                    if line.startswith('{') or (len(line) > 100 and '=' not in line):
                        # Posible texto cifrado
                        encrypted_part = '\n'.join(lines[i:])
                        encrypted_filename = os.path.join(results_dir, f"texto_cifrado_{timestamp}.enc")
                        with open(encrypted_filename, 'w', encoding='utf-8') as f:
                            f.write(encrypted_part)
                        break
            
            messagebox.showinfo("Éxito", 
                              f"Resultados guardados en:\n{results_dir}\n"
                              f"Archivo principal: {os.path.basename(result_filename)}")
            self.log_operation(f"Resultados completos guardados en: {results_dir}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar ambos resultados: {str(e)}")
    
    # ========== MÉTODOS DE GESTIÓN DE CLAVES ==========
    
    def generate_keys(self):
        """Generar un nuevo par de claves y guardar automáticamente"""
        try:
            key_name = self.key_name_entry.get().strip()
            if not key_name:
                messagebox.showwarning("Advertencia", "Ingrese un nombre para el par de claves")
                return
                
            algorithm = self.algo_var.get()
            
            if algorithm == "RSA":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                key_size = "2048 bits"
                algo_folder = "rsa"
            else:  # ECC
                private_key = ec.generate_private_key(ec.SECP256R1())
                key_size = "P-256"
                algo_folder = "ecc"
                
            public_key = private_key.public_key()
            
            # Crear nombre de archivo seguro
            safe_key_name = "".join(c for c in key_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_base = f"{safe_key_name}_{timestamp}"
            
            # Rutas de archivo
            priv_key_path = os.path.join(self.keys_folder, algo_folder, f"{filename_base}_private.pem")
            pub_key_path = os.path.join(self.keys_folder, algo_folder, f"{filename_base}_public.pem")
            
            # Guardar claves en archivos
            with open(priv_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(pub_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            # Almacenar en el diccionario
            key_data = {
                'private_key': private_key,
                'public_key': public_key,
                'algorithm': algorithm,
                'created': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'file_paths': {
                    'private_key_path': priv_key_path,
                    'public_key_path': pub_key_path
                }
            }
            
            self.key_pairs[key_name] = key_data
            
            # Guardar en índice
            self.save_key_to_index(key_name, key_data, priv_key_path, pub_key_path)
            
            # Actualizar interfaz
            self.update_key_selector()
            self.key_selector.set(key_name)
            self.select_key_pair(key_name)
            
            self.keys_info.configure(state="normal")
            self.keys_info.delete("1.0", "end")
            self.keys_info.insert("1.0", f"✓ Par de claves '{key_name}' generado y guardado\n")
            self.keys_info.insert("end", f"Algoritmo: {algorithm} ({key_size})\n")
            self.keys_info.insert("end", f"Ubicación: {algo_folder}/\n")
            self.keys_info.insert("end", f"Archivos: {filename_base}_[private|public].pem\n")
            self.keys_info.insert("end", f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.keys_info.configure(state="disabled")
            
            self.log_operation(f"Generadas y guardadas claves {algorithm} - {key_name}")
            messagebox.showinfo("Éxito", 
                              f"Par de claves '{key_name}' generado y guardado automáticamente\n"
                              f"Ubicación: {os.path.join(self.keys_folder, algo_folder)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar claves: {str(e)}")
    
    def save_current_key_auto(self):
        """Guardar la clave actual automáticamente en la carpeta de llaves"""
        if self.private_key is None or self.current_key_name is None:
            messagebox.showwarning("Advertencia", "No hay clave seleccionada para guardar")
            return
            
        try:
            key_data = self.key_pairs[self.current_key_name]
            algorithm = key_data['algorithm']
            algo_folder = "rsa" if algorithm == "RSA" else "ecc"
            
            # Si ya tiene rutas de archivo, usar esas
            if 'file_paths' in key_data and key_data['file_paths'].get('private_key_path'):
                priv_key_path = key_data['file_paths']['private_key_path']
                pub_key_path = key_data['file_paths']['public_key_path']
            else:
                # Crear nuevas rutas
                safe_key_name = "".join(c for c in self.current_key_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename_base = f"{safe_key_name}_{timestamp}"
                
                priv_key_path = os.path.join(self.keys_folder, algo_folder, f"{filename_base}_private.pem")
                pub_key_path = os.path.join(self.keys_folder, algo_folder, f"{filename_base}_public.pem")
            
            # Guardar archivos
            with open(priv_key_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(pub_key_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            # Actualizar datos
            key_data['file_paths'] = {
                'private_key_path': priv_key_path,
                'public_key_path': pub_key_path
            }
            
            # Actualizar índice
            self.save_key_to_index(self.current_key_name, key_data, priv_key_path, pub_key_path)
            
            self.log_operation(f"Clave '{self.current_key_name}' guardada automáticamente")
            messagebox.showinfo("Éxito", f"Clave guardada en:\n{priv_key_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar clave: {str(e)}")
    
    def save_all_keys_auto(self):
        """Guardar todas las claves en la carpeta de llaves"""
        try:
            saved_count = 0
            for key_name, key_data in self.key_pairs.items():
                try:
                    if key_data.get('private_key') is not None:
                        self.current_key_name = key_name
                        self.private_key = key_data['private_key']
                        self.public_key = key_data['public_key']
                        self.save_current_key_auto()
                        saved_count += 1
                except Exception as e:
                    print(f"✗ Error guardando clave {key_name}: {e}")
                    continue
            
            self.log_operation(f"Guardadas {saved_count} claves automáticamente")
            messagebox.showinfo("Éxito", f"Se guardaron {saved_count} claves en la carpeta de llaves")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar todas las claves: {str(e)}")
    
    def open_keys_folder(self):
        """Abrir la carpeta de llaves en el explorador de archivos"""
        try:
            if os.path.exists(self.keys_folder):
                os.startfile(self.keys_folder)  # Windows
            else:
                messagebox.showwarning("Advertencia", "La carpeta de llaves no existe")
        except OSError:
            try:
                # Alternativa para otros sistemas operativos
                import subprocess
                subprocess.run(['open', self.keys_folder])  # macOS
            except Exception:
                try:
                    subprocess.run(['xdg-open', self.keys_folder])  # Linux
                except Exception:
                    messagebox.showinfo("Información", 
                                      f"La carpeta de llaves está en:\n{os.path.abspath(self.keys_folder)}")
    
    def create_backup(self):
        """Crear un backup de todas las llaves"""
        try:
            backup_folder = os.path.join(self.keys_folder, "backup", f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            os.makedirs(backup_folder)
            
            # Copiar toda la estructura de llaves
            for root, dirs, files in os.walk(self.keys_folder):
                # No copiar la carpeta de backup actual
                if "backup" in root and root != self.keys_folder:
                    continue
                    
                for file in files:
                    if file.endswith(('.pem', '.json')):
                        src_path = os.path.join(root, file)
                        rel_path = os.path.relpath(src_path, self.keys_folder)
                        dst_path = os.path.join(backup_folder, rel_path)
                        
                        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                        shutil.copy2(src_path, dst_path)
            
            self.log_operation(f"Backup creado: {backup_folder}")
            messagebox.showinfo("Éxito", f"Backup creado en:\n{backup_folder}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al crear backup: {str(e)}")
    
    def refresh_keys(self):
        """Recargar claves desde la carpeta"""
        try:
            old_count = len(self.key_pairs)
            self.key_pairs.clear()
            self.load_existing_keys()
            new_count = len(self.key_pairs)
            
            self.log_operation(f"Claves recargadas: {new_count} encontradas")
            messagebox.showinfo("Éxito", f"Claves recargadas\n{new_count} claves encontradas en la carpeta")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al recargar claves: {str(e)}")
    
    def save_private_key_manual(self):
        """Guardar clave privada manualmente (diálogo de archivo)"""
        if self.private_key is None:
            messagebox.showwarning("Advertencia", "No hay clave privada para guardar")
            return
            
        try:
            # Sugerir nombre en la carpeta de llaves
            initial_dir = os.path.join(self.keys_folder, "rsa")
            filename = filedialog.asksaveasfilename(
                initialdir=initial_dir,
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, "wb") as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                messagebox.showinfo("Éxito", f"Clave privada guardada en: {filename}")
                self.log_operation(f"Clave privada guardada manualmente: {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar clave privada: {str(e)}")
    
    def save_public_key_manual(self):
        """Guardar clave pública manualmente (diálogo de archivo)"""
        if self.public_key is None:
            messagebox.showwarning("Advertencia", "No hay clave pública para guardar")
            return
            
        try:
            initial_dir = os.path.join(self.keys_folder, "rsa")
            filename = filedialog.asksaveasfilename(
                initialdir=initial_dir,
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, "wb") as f:
                    f.write(self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ))
                messagebox.showinfo("Éxito", f"Clave pública guardada en: {filename}")
                self.log_operation(f"Clave pública guardada manualmente: {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar clave pública: {str(e)}")
    
    def load_private_key_manual(self):
        """Cargar clave privada manualmente"""
        try:
            initial_dir = self.keys_folder
            filename = filedialog.askopenfilename(
                initialdir=initial_dir,
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, "rb") as f:
                    private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None
                    )
                
                key_name = f"cargada_{datetime.now().strftime('%H%M%S')}"
                self.key_pairs[key_name] = {
                    'private_key': private_key,
                    'public_key': private_key.public_key(),
                    'algorithm': 'RSA',
                    'created': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'file_paths': {'private_key_path': filename}
                }
                
                self.update_key_selector()
                self.key_selector.set(key_name)
                self.select_key_pair(key_name)
                
                self.log_operation(f"Clave privada cargada manualmente: {filename}")
                messagebox.showinfo("Éxito", "Clave privada cargada exitosamente")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar clave privada: {str(e)}")
    
    def load_public_key_manual(self):
        """Cargar clave pública manualmente"""
        try:
            initial_dir = self.keys_folder
            filename = filedialog.askopenfilename(
                initialdir=initial_dir,
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, "rb") as f:
                    public_key = serialization.load_pem_public_key(f.read())
                
                key_name = f"publica_{datetime.now().strftime('%H%M%S')}"
                self.key_pairs[key_name] = {
                    'private_key': None,
                    'public_key': public_key,
                    'algorithm': 'RSA',
                    'created': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'file_paths': {'public_key_path': filename}
                }
                
                self.update_key_selector()
                self.key_selector.set(key_name)
                self.select_key_pair(key_name)
                
                self.log_operation(f"Clave pública cargada manualmente: {filename}")
                messagebox.showinfo("Éxito", "Clave pública cargada exitosamente")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar clave pública: {str(e)}")

    def update_key_selector(self):
        """Actualizar el selector de claves"""
        key_names = list(self.key_pairs.keys())
        self.key_selector.configure(values=key_names)
    
    def select_key_pair(self, choice):
        """Seleccionar un par de claves del diccionario"""
        if choice in self.key_pairs:
            key_data = self.key_pairs[choice]
            self.private_key = key_data['private_key']
            self.public_key = key_data['public_key']
            self.current_key_name = choice
            
            # Mostrar información detallada
            self.keys_info.configure(state="normal")
            self.keys_info.delete("1.0", "end")
            self.keys_info.insert("1.0", f"✓ Clave seleccionada: {choice}\n")
            self.keys_info.insert("end", f"Algoritmo: {key_data['algorithm']}\n")
            self.keys_info.insert("end", f"Creada: {key_data['created']}\n")
            
            if 'file_paths' in key_data:
                if key_data['file_paths'].get('private_key_path'):
                    self.keys_info.insert("end", f"Privada: {os.path.basename(key_data['file_paths']['private_key_path'])}\n")
                if key_data['file_paths'].get('public_key_path'):
                    self.keys_info.insert("end", f"Pública: {os.path.basename(key_data['file_paths']['public_key_path'])}")
            
            self.keys_info.configure(state="disabled")
            
            self.log_operation(f"Clave seleccionada: {choice}")

    def export_all_keys(self):
        """Exportar todas las claves a un archivo JSON"""
        try:
            # Sugerir la carpeta exported
            initial_dir = os.path.join(self.keys_folder, "exported")
            filename = filedialog.asksaveasfilename(
                initialdir=initial_dir,
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if filename:
                export_data = {}
                for name, key_data in self.key_pairs.items():
                    # Solo exportar si tenemos las rutas de archivo
                    if 'file_paths' in key_data:
                        export_data[name] = {
                            'algorithm': key_data['algorithm'],
                            'created': key_data['created'],
                            'file_paths': key_data['file_paths']
                        }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                messagebox.showinfo("Éxito", f"Todas las claves exportadas a: {filename}")
                self.log_operation(f"Claves exportadas: {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar claves: {str(e)}")

    def load_file_for_encryption(self):
        """Cargar archivo para cifrado/descifrado - soporte binario"""
        try:
            filename = filedialog.askopenfilename()
            if filename:
                file_size = os.path.getsize(filename)
                
                if file_size > 10 * 1024 * 1024:  # 10MB limit
                    messagebox.showwarning("Advertencia", "Archivo muy grande para cifrado (límite 10MB)")
                    return
                
                # Leer como binario
                with open(filename, 'rb') as f:
                    content = f.read()
                
                # Mostrar información del archivo
                self.file_info_label.configure(
                    text=f"Archivo: {os.path.basename(filename)} | Tamaño: {file_size} bytes | Binario: {'Sí' if file_size > 1000 else 'No'}"
                )
                self.file_info_frame.pack(fill="x", padx=20, pady=5)
                
                # Mostrar contenido (texto) o información (binario)
                self.encrypt_text.delete('1.0', 'end')
                if file_size < 1000 and self.is_text_file(content):
                    self.encrypt_text.insert('1.0', content.decode('utf-8', errors='ignore'))
                else:
                    self.encrypt_text.insert('1.0', f"[Archivo binario - {file_size} bytes]\n")
                    self.encrypt_text.insert('end', f"Contenido en base64:\n{base64.b64encode(content).decode('utf-8')}")
                
                self.log_operation(f"Archivo cargado para cifrado: {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar archivo: {str(e)}")
    
    def is_text_file(self, data):
        """Verificar si los datos son texto legible"""
        try:
            data.decode('utf-8')
            return True
        except UnicodeDecodeError:
            return False

    def sign_message(self):
        """Firmar mensaje usando clave privada"""
        if self.private_key is None:
            messagebox.showwarning("Advertencia", "Debe cargar una clave privada primero")
            return
            
        try:
            message = self.sign_text.get('1.0', 'end-1c').encode('utf-8')
            if not message.strip():
                messagebox.showwarning("Advertencia", "No hay mensaje para firmar")
                return
            
            signature = self.private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            self.signature_text.delete('1.0', 'end')
            self.signature_text.insert('1.0', signature_b64)
            
            self.log_operation("Mensaje firmado digitalmente")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al firmar: {str(e)}")
    
    def verify_signature(self):
        """Verificar firma usando clave pública"""
        if self.public_key is None:
            messagebox.showwarning("Advertencia", "Debe cargar una clave pública primero")
            return
            
        try:
            message = self.sign_text.get('1.0', 'end-1c').encode('utf-8')
            signature_b64 = self.signature_text.get('1.0', 'end-1c').strip()
            
            if not message.strip():
                messagebox.showwarning("Advertencia", "No hay mensaje para verificar")
                return
            if not signature_b64:
                messagebox.showwarning("Advertencia", "No hay firma para verificar")
                return
            
            signature = base64.b64decode(signature_b64)
            
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            self.verify_result.configure(text="✓ FIRMA VÁLIDA - El mensaje es auténtico e íntegro", 
                                       text_color="green")
            self.log_operation("Firma verificada exitosamente - VÁLIDA")
            
        except InvalidSignature:
            self.verify_result.configure(text="✗ FIRMA INVÁLIDA - El mensaje ha sido alterado", 
                                       text_color="red")
            self.log_operation("Firma verificada - INVÁLIDA")
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar: {str(e)}")
    
    def start_encryption_animation(self):
        """Iniciar animación del proceso de cifrado"""
        thread = threading.Thread(target=self.run_encryption_animation)
        thread.daemon = True
        thread.start()
    
    def run_encryption_animation(self):
        """Ejecutar animación de cifrado paso a paso"""
        try:
            self.animation_display.configure(state="normal")
            self.animation_display.delete("1.0", "end")
            
            plaintext = self.animation_input.get("1.0", "end-1c")
            if not plaintext.strip():
                messagebox.showwarning("Advertencia", "Ingrese texto para animar")
                return
            
            steps = [
                "🔍 Obteniendo texto plano...",
                f"📝 Texto plano: '{plaintext}'",
                "🔄 Convirtiendo a bytes...",
                f"🔢 Bytes: {list(plaintext.encode('utf-8'))}",
                "🔑 Obteniendo clave pública...",
                "⚙️ Configurando padding OAEP...",
                "🔒 Cifrando con RSA...",
                "📊 Generando texto cifrado...",
                "✅ Proceso completado!"
            ]
            
            for i, step in enumerate(steps):
                self.animation_display.insert("end", f"Paso {i+1}: {step}\n")
                self.animation_display.see("end")
                self.animation_progress.set((i + 1) / len(steps))
                self.animation_status.configure(text=step)
                time.sleep(1.5)
            
            # Mostrar resultado final
            if self.public_key:
                # Usar cifrado simple para la animación
                ciphertext = self.public_key.encrypt(
                    plaintext.encode('utf-8'),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                encrypted_b64 = base64.b64encode(ciphertext).decode('utf-8')
                self.animation_display.insert("end", f"\n🎉 Texto cifrado (base64):\n{encrypted_b64}\n")
            else:
                self.animation_display.insert("end", "\n⚠️ No hay clave pública para cifrado real\n")
            
            self.animation_display.configure(state="disabled")
            self.log_operation("Animación de cifrado completada")
            
        except Exception as e:
            self.animation_display.insert("end", f"\n❌ Error: {str(e)}\n")
            self.animation_display.configure(state="disabled")
    
    def start_decryption_animation(self):
        """Iniciar animación del proceso de descifrado"""
        thread = threading.Thread(target=self.run_decryption_animation)
        thread.daemon = True
        thread.start()
    
    def run_decryption_animation(self):
        """Ejecutar animación de descifrado paso a paso"""
        try:
            self.animation_display.configure(state="normal")
            self.animation_display.delete("1.0", "end")
            
            ciphertext_b64 = self.animation_input.get("1.0", "end-1c").strip()
            if not ciphertext_b64:
                messagebox.showwarning("Advertencia", "Ingrese texto cifrado para animar")
                return
            
            steps = [
                "🔍 Obteniendo texto cifrado...",
                "📊 Decodificando base64...",
                "🔢 Convirtiendo a bytes cifrados...",
                "🔑 Obteniendo clave privada...",
                "⚙️ Configurando padding OAEP...",
                "🔓 Descifrando con RSA...",
                "🔄 Convirtiendo bytes a texto...",
                "✅ Proceso completado!"
            ]
            
            for i, step in enumerate(steps):
                self.animation_display.insert("end", f"Paso {i+1}: {step}\n")
                self.animation_display.see("end")
                self.animation_progress.set((i + 1) / len(steps))
                self.animation_status.configure(text=step)
                time.sleep(1.5)
            
            # Mostrar resultado final
            if self.private_key:
                try:
                    ciphertext = base64.b64decode(ciphertext_b64)
                    plaintext = self.private_key.decrypt(
                        ciphertext,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    self.animation_display.insert("end", f"\n🎉 Texto descifrado: '{plaintext.decode('utf-8')}'\n")
                except Exception as e:
                    self.animation_display.insert("end", f"\n❌ Error en descifrado: {str(e)}\n")
            else:
                self.animation_display.insert("end", "\n⚠️ No hay clave privada para descifrado real\n")
            
            self.animation_display.configure(state="disabled")
            self.log_operation("Animación de descifrado completada")
            
        except Exception as e:
            self.animation_display.insert("end", f"\n❌ Error: {str(e)}\n")
            self.animation_display.configure(state="disabled")
    
    def clear_animation(self):
        """Limpiar la animación"""
        self.animation_display.configure(state="normal")
        self.animation_display.delete("1.0", "end")
        self.animation_display.insert("1.0", "La animación del proceso criptográfico aparecerá aquí...\n\n")
        self.animation_display.configure(state="disabled")
        self.animation_progress.set(0)
        self.animation_status.configure(text="Listo para animar...")
    
    def log_operation(self, operation):
        """Registrar una operación en el log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {operation}"
        self.operation_log.append(log_entry)
        
        # Actualizar display de logs
        self.logs_display.configure(state="normal")
        self.logs_display.insert("end", log_entry + "\n")
        self.logs_display.see("end")
        self.logs_display.configure(state="disabled")
    
    def clear_logs(self):
        """Limpiar todos los logs"""
        self.operation_log.clear()
        self.logs_display.configure(state="normal")
        self.logs_display.delete("1.0", "end")
        self.logs_display.configure(state="disabled")
        self.log_operation("Registros limpiados")
    
    def export_logs(self):
        """Exportar logs a archivo"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    for log_entry in self.operation_log:
                        f.write(log_entry + "\n")
                messagebox.showinfo("Éxito", f"Logs exportados a: {filename}")
                self.log_operation(f"Logs exportados a {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar logs: {str(e)}")
    
    def generate_statistics(self):
        """Generar estadísticas de uso"""
        try:
            total_operations = len(self.operation_log)
            key_operations = sum(1 for op in self.operation_log if "clave" in op.lower())
            encrypt_operations = sum(1 for op in self.operation_log if "cifrad" in op.lower())
            sign_operations = sum(1 for op in self.operation_log if "firm" in op.lower())
            
            stats_text = f"""
📊 ESTADÍSTICAS DE USO:

• Operaciones totales: {total_operations}
• Operaciones con claves: {key_operations}
• Operaciones de cifrado: {encrypt_operations}
• Operaciones de firma: {sign_operations}
• Pares de claves almacenados: {len(self.key_pairs)}

⏰ Período de registro: Desde {self.operation_log[0].split(']')[0][1:] if self.operation_log else 'N/A'}
"""
            
            self.stats_display.configure(state="normal")
            self.stats_display.delete("1.0", "end")
            self.stats_display.insert("1.0", stats_text)
            self.stats_display.configure(state="disabled")
            
            self.log_operation("Estadísticas generadas")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar estadísticas: {str(e)}")
    
    def clear_encrypt_text(self):
        """Limpiar áreas de texto de cifrado"""
        self.encrypt_text.delete('1.0', 'end')
        self.encrypt_result.delete('1.0', 'end')
        self.file_info_frame.pack_forget()
    
    def clear_sign_text(self):
        """Limpiar áreas de texto de firma"""
        self.sign_text.delete('1.0', 'end')
        self.signature_text.delete('1.0', 'end')
        self.verify_result.configure(text="")
    
    def load_file_for_signing(self):
        """Cargar archivo para firmar"""
        try:
            filename = filedialog.askopenfilename()
            if filename:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.sign_text.delete('1.0', 'end')
                self.sign_text.insert('1.0', content)
                self.log_operation(f"Archivo cargado para firma: {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar archivo: {str(e)}")

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()