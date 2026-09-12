# docs-signer

Posprocesador de PDFs con firma visible, hashes SHA-256 y firma
criptografica Ed25519. Preserva el original y anade un manifiesto
de procedencia APM-1.

## Caracteristicas

- Firma visible al final del PDF (autoria, motor, hashes).
- Hash SHA-256 del PDF fuente, del manifiesto y del PDF final.
- Firma Ed25519 del manifiesto canonico y del PDF final.
- Modos: declared, hash, sign-local, auto.
- Procesamiento por lotes de una carpeta completa.
- Verificacion criptografica de integridad.

## Instalacion

    git clone https://github.com/xyphrnyx/docs-signer.git
    cd docs-signer
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

## Uso

Generar par de claves (solo una vez):

    python akaath_pdf_signer.py keygen --private-key ~/.akaath/akaath_private.pem --public-key ~/.akaath/akaath_public.pem

Firmar un PDF:

    python akaath_pdf_signer.py stamp documento.pdf --mode auto --private-key ~/.akaath/akaath_private.pem

Verificar:

    python akaath_pdf_signer.py verify --pdf documento_AKaaTH_firmado.pdf --public-key ~/.akaath/akaath_public.pem

## Licencia

Este proyecto esta bajo la licencia Apache 2.0. Ver LICENSE y NOTICE.
