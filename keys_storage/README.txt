📁 CARPETA DE ALMACENAMIENTO DE LLAVES

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
