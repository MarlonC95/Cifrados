import os
def check_environment():
    """Verificar y configurar el entorno"""
    print("🔍 Verificando entorno...")
    
    # Verificar si existe la carpeta de llaves
    keys_folder = "keys_storage"
    if not os.path.exists(keys_folder):
        print("📁 Creando carpeta de llaves por primera vez...")
        try:
            from setup_directories import setup_environment
            setup_environment()
        except ImportError:
            print("⚠️ Ejecute primero: python setup_directories.py")
            return False
    

def main():
    """Función principal"""
    print("=" * 60)
    print("🔐 Sistema Avanzado de Criptografía Asimétrica")
    print("📁 Versión 2.0 - Con Gestión Automática de Llaves")
    print("=" * 60)
    
    # Verificar entorno
    if not check_environment():
        input("Presiona Enter para salir...")
        return
    
    # Importar y ejecutar aplicación
    try:
        from Encriptador import CryptoApp
        import customtkinter as ctk
        
        print("🚀 Iniciando aplicación...")
        
        # Configuración inicial
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")
        
        # Crear y ejecutar aplicación
        app = CryptoApp()
        app.mainloop()
        
    except ImportError as e:
        print(f"✗ Error de importación: {e}")
        input("Presiona Enter para salir...")
    except Exception as e:
        print(f"✗ Error inesperado: {e}")
        input("Presiona Enter para salir...")

if __name__ == "__main__":
    main()