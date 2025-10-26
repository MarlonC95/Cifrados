import customtkinter as ctk
from tkinter import filedialog, messagebox, scrolledtext
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import base64

# Configuración de customtkinter
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Sistema de Criptografía Asimétrica")
        self.geometry("900x700")
        self.resizable(True, True)
        
        # Variables para almacenar claves
        self.private_key = None
        self.public_key = None
        
        # Crear pestañas
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Crear las pestañas
        self.tab_keys = self.tabview.add("Gestión de Claves")
        self.tab_encrypt = self.tabview.add("Cifrar/Descifrar")
        self.tab_sign = self.tabview.add("Firmar/Verificar")
        
        # Configurar cada pestaña
        self.setup_keys_tab()
        self.setup_encrypt_tab()
        self.setup_sign_tab()
        
    def setup_keys_tab(self):
        """Configurar la pestaña de gestión de claves"""
        # Título
        title_label = ctk.CTkLabel(self.tab_keys, text="Gestión de Claves RSA", 
                                  font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=10)
        
        # Frame para generar claves
        gen_frame = ctk.CTkFrame(self.tab_keys)
        gen_frame.pack(fill="x", padx=20, pady=10)
        
        gen_label = ctk.CTkLabel(gen_frame, text="Generar Nuevas Claves", 
                                font=ctk.CTkFont(size=16, weight="bold"))
        gen_label.pack(pady=10)
        
        # Botón para generar claves
        gen_button = ctk.CTkButton(gen_frame, text="Generar Par de Claves", 
                                  command=self.generate_keys)
        gen_button.pack(pady=10)
        
        # Frame para guardar claves
        save_frame = ctk.CTkFrame(self.tab_keys)
        save_frame.pack(fill="x", padx=20, pady=10)
        
        save_label = ctk.CTkLabel(save_frame, text="Guardar Claves", 
                                 font=ctk.CTkFont(size=16, weight="bold"))
        save_label.pack(pady=10)
        
        # Botones para guardar claves
        save_buttons_frame = ctk.CTkFrame(save_frame)
        save_buttons_frame.pack(pady=10)
        
        save_private_btn = ctk.CTkButton(save_buttons_frame, text="Guardar Clave Privada",
                                        command=self.save_private_key)
        save_private_btn.pack(side="left", padx=5)
        
        save_public_btn = ctk.CTkButton(save_buttons_frame, text="Guardar Clave Pública",
                                       command=self.save_public_key)
        save_public_btn.pack(side="left", padx=5)
        
        # Frame para cargar claves
        load_frame = ctk.CTkFrame(self.tab_keys)
        load_frame.pack(fill="x", padx=20, pady=10)
        
        load_label = ctk.CTkLabel(load_frame, text="Cargar Claves", 
                                 font=ctk.CTkFont(size=16, weight="bold"))
        load_label.pack(pady=10)
        
        # Botones para cargar claves
        load_buttons_frame = ctk.CTkFrame(load_frame)
        load_buttons_frame.pack(pady=10)
        
        load_private_btn = ctk.CTkButton(load_buttons_frame, text="Cargar Clave Privada",
                                        command=self.load_private_key)
        load_private_btn.pack(side="left", padx=5)
        
        load_public_btn = ctk.CTkButton(load_buttons_frame, text="Cargar Clave Pública",
                                       command=self.load_public_key)
        load_public_btn.pack(side="left", padx=5)
        
        # Área de información
        self.keys_info = ctk.CTkTextbox(self.tab_keys, height=100)
        self.keys_info.pack(fill="x", padx=20, pady=10)
        self.keys_info.insert("1.0", "Información de claves aparecerá aquí...")
        self.keys_info.configure(state="disabled")
        
    def setup_encrypt_tab(self):
        """Configurar la pestaña de cifrado/descifrado"""
        # Título
        title_label = ctk.CTkLabel(self.tab_encrypt, text="Cifrado y Descifrado", 
                                  font=ctk.CTkFont(size=20, weight="bold"))
        title_label.pack(pady=10)
        
        # Frame para entrada de texto
        input_frame = ctk.CTkFrame(self.tab_encrypt)
        input_frame.pack(fill="x", padx=20, pady=10)
        
        input_label = ctk.CTkLabel(input_frame, text="Texto a Cifrar/Descifrar:")
        input_label.pack(anchor="w", pady=5)
        
        self.encrypt_text = scrolledtext.ScrolledText(input_frame, height=8)
        self.encrypt_text.pack(fill="x", pady=5)
        
        # Botones para archivos
        file_buttons_frame = ctk.CTkFrame(input_frame)
        file_buttons_frame.pack(fill="x", pady=5)
        
        load_file_btn = ctk.CTkButton(file_buttons_frame, text="Cargar Archivo",
                                     command=self.load_file_for_encryption)
        load_file_btn.pack(side="left", padx=5)
        
        save_file_btn = ctk.CTkButton(file_buttons_frame, text="Guardar como Archivo",
                                     command=self.save_encrypted_text)
        save_file_btn.pack(side="left", padx=5)
        
        # Botones de operación
        op_buttons_frame = ctk.CTkFrame(self.tab_encrypt)
        op_buttons_frame.pack(fill="x", padx=20, pady=10)
        
        encrypt_btn = ctk.CTkButton(op_buttons_frame, text="Cifrar", 
                                   command=self.encrypt_text_func)
        encrypt_btn.pack(side="left", padx=5)
        
        decrypt_btn = ctk.CTkButton(op_buttons_frame, text="Descifrar", 
                                   command=self.decrypt_text_func)
        decrypt_btn.pack(side="left", padx=5)
        
        clear_btn = ctk.CTkButton(op_buttons_frame, text="Limpiar", 
                                 command=self.clear_encrypt_text)
        clear_btn.pack(side="left", padx=5)
        
        # Frame para resultado
        result_frame = ctk.CTkFrame(self.tab_encrypt)
        result_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        result_label = ctk.CTkLabel(result_frame, text="Resultado:")
        result_label.pack(anchor="w", pady=5)
        
        self.encrypt_result = scrolledtext.ScrolledText(result_frame, height=8)
        self.encrypt_result.pack(fill="both", expand=True, pady=5)
        
    def setup_sign_tab(self):
        """Configurar la pestaña de firma digital"""
        # Título
        title_label = ctk.CTkLabel(self.tab_sign, text="Firma Digital", 
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
        
        sign_label = ctk.CTkLabel(sign_frame, text="Firma:")
        sign_label.pack(anchor="w", pady=5)
        
        self.signature_text = ctk.CTkTextbox(sign_frame, height=4)
        self.signature_text.pack(fill="x", pady=5)
        
        # Botones de operación
        op_buttons_frame = ctk.CTkFrame(self.tab_sign)
        op_buttons_frame.pack(fill="x", padx=20, pady=10)
        
        sign_btn = ctk.CTkButton(op_buttons_frame, text="Firmar Mensaje", 
                                command=self.sign_message)
        sign_btn.pack(side="left", padx=5)
        
        verify_btn = ctk.CTkButton(op_buttons_frame, text="Verificar Firma", 
                                  command=self.verify_signature)
        verify_btn.pack(side="left", padx=5)
        
        clear_btn = ctk.CTkButton(op_buttons_frame, text="Limpiar", 
                                 command=self.clear_sign_text)
        clear_btn.pack(side="left", padx=5)
        
        # Resultado de verificación
        self.verify_result = ctk.CTkLabel(self.tab_sign, text="", 
                                         font=ctk.CTkFont(size=14, weight="bold"))
        self.verify_result.pack(pady=10)
        
    # Métodos para gestión de claves
    def generate_keys(self):
        """Generar un nuevo par de claves RSA"""
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
            
            self.keys_info.configure(state="normal")
            self.keys_info.delete("1.0", "end")
            self.keys_info.insert("1.0", "✓ Par de claves generado exitosamente\n")
            self.keys_info.insert("end", f"Tamaño de clave: 2048 bits\n")
            self.keys_info.insert("end", f"Algoritmo: RSA\n")
            self.keys_info.insert("end", "Puede guardar las claves en archivos .pem")
            self.keys_info.configure(state="disabled")
            
            messagebox.showinfo("Éxito", "Par de claves generado exitosamente")
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al generar claves: {str(e)}")
    
    def save_private_key(self):
        """Guardar la clave privada en un archivo"""
        if self.private_key is None:
            messagebox.showwarning("Advertencia", "No hay clave privada para guardar")
            return
            
        try:
            filename = filedialog.asksaveasfilename(
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
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar clave privada: {str(e)}")
    
    def save_public_key(self):
        """Guardar la clave pública en un archivo"""
        if self.public_key is None:
            messagebox.showwarning("Advertencia", "No hay clave pública para guardar")
            return
            
        try:
            filename = filedialog.asksaveasfilename(
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
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar clave pública: {str(e)}")
    
    def load_private_key(self):
        """Cargar clave privada desde archivo"""
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, "rb") as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None
                    )
                self.public_key = self.private_key.public_key()
                
                self.keys_info.configure(state="normal")
                self.keys_info.delete("1.0", "end")
                self.keys_info.insert("1.0", f"✓ Clave privada cargada desde: {filename}\n")
                self.keys_info.insert("end", "Clave pública derivada automáticamente")
                self.keys_info.configure(state="disabled")
                
                messagebox.showinfo("Éxito", "Clave privada cargada exitosamente")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar clave privada: {str(e)}")
    
    def load_public_key(self):
        """Cargar clave pública desde archivo"""
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, "rb") as f:
                    self.public_key = serialization.load_pem_public_key(f.read())
                
                self.keys_info.configure(state="normal")
                self.keys_info.delete("1.0", "end")
                self.keys_info.insert("1.0", f"✓ Clave pública cargada desde: {filename}\n")
                self.keys_info.insert("end", "Nota: Solo se puede cifrar y verificar con esta clave")
                self.keys_info.configure(state="disabled")
                
                messagebox.showinfo("Éxito", "Clave pública cargada exitosamente")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar clave pública: {str(e)}")
    
    # Métodos para cifrado/descifrado
    def load_file_for_encryption(self):
        """Cargar archivo para cifrado/descifrado"""
        try:
            filename = filedialog.askopenfilename()
            if filename:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.encrypt_text.delete('1.0', 'end')
                self.encrypt_text.insert('1.0', content)
                messagebox.showinfo("Éxito", f"Archivo cargado: {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar archivo: {str(e)}")
    
    def save_encrypted_text(self):
        """Guardar texto cifrado como archivo"""
        try:
            content = self.encrypt_result.get('1.0', 'end-1c')
            if not content.strip():
                messagebox.showwarning("Advertencia", "No hay contenido para guardar")
                return
                
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Éxito", f"Contenido guardado en: {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al guardar archivo: {str(e)}")
    
    def encrypt_text_func(self):
        """Cifrar texto usando clave pública"""
        if self.public_key is None:
            messagebox.showwarning("Advertencia", "Debe cargar una clave pública primero")
            return
            
        try:
            plaintext = self.encrypt_text.get('1.0', 'end-1c').encode('utf-8')
            if not plaintext.strip():
                messagebox.showwarning("Advertencia", "No hay texto para cifrar")
                return
            
            # RSA tiene límites de tamaño, así que ciframos en bloques si es necesario
            if len(plaintext) > 190:  # Límite para RSA 2048
                messagebox.showwarning("Advertencia", "El texto es muy largo para cifrado RSA directo")
                return
            
            ciphertext = self.public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Convertir a base64 para mejor visualización
            encrypted_b64 = base64.b64encode(ciphertext).decode('utf-8')
            
            self.encrypt_result.delete('1.0', 'end')
            self.encrypt_result.insert('1.0', encrypted_b64)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al cifrar: {str(e)}")
    
    def decrypt_text_func(self):
        """Descifrar texto usando clave privada"""
        if self.private_key is None:
            messagebox.showwarning("Advertencia", "Debe cargar una clave privada primero")
            return
            
        try:
            ciphertext_b64 = self.encrypt_text.get('1.0', 'end-1c').strip()
            if not ciphertext_b64:
                messagebox.showwarning("Advertencia", "No hay texto cifrado para descifrar")
                return
            
            ciphertext = base64.b64decode(ciphertext_b64)
            
            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            self.encrypt_result.delete('1.0', 'end')
            self.encrypt_result.insert('1.0', plaintext.decode('utf-8'))
            
        except Exception as e:
            messagebox.showerror("Error", f"Error al descifrar: {str(e)}")
    
    def clear_encrypt_text(self):
        """Limpiar áreas de texto de cifrado"""
        self.encrypt_text.delete('1.0', 'end')
        self.encrypt_result.delete('1.0', 'end')
    
    # Métodos para firma digital
    def load_file_for_signing(self):
        """Cargar archivo para firmar"""
        try:
            filename = filedialog.askopenfilename()
            if filename:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.sign_text.delete('1.0', 'end')
                self.sign_text.insert('1.0', content)
                messagebox.showinfo("Éxito", f"Archivo cargado: {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Error al cargar archivo: {str(e)}")
    
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
            
            # Convertir a base64 para mejor visualización
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            self.signature_text.delete('1.0', 'end')
            self.signature_text.insert('1.0', signature_b64)
            
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
            
            self.verify_result.configure(text="✓ FIRMA VÁLIDA - El mensaje es auténtico", 
                                       text_color="green")
            
        except InvalidSignature:
            self.verify_result.configure(text="✗ FIRMA INVÁLIDA - El mensaje ha sido alterado", 
                                       text_color="red")
        except Exception as e:
            messagebox.showerror("Error", f"Error al verificar: {str(e)}")
    
    def clear_sign_text(self):
        """Limpiar áreas de texto de firma"""
        self.sign_text.delete('1.0', 'end')
        self.signature_text.delete('1.0', 'end')
        self.verify_result.configure(text="")

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()