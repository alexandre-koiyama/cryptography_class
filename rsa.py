import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os

# Function to generate RSA keys
# Input: None
# Description: Generates a pair of RSA keys (private and public), saves them to files
# Output: String message indicating success
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)

    return "Private and Public keys generated!"

# Function to encrypt data chunks
# Input: Chunk of data (bytes), public key
# Description: Encrypts a chunk of data using the public key and RSA encryption with OAEP padding
# Output: Encrypted chunk (bytes)
def encrypt_chunk(chunk, public_key):
    return public_key.encrypt(
        chunk,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Function to encrypt file content
# Input: File content (bytes), public key, chunk size (int, optional)
# Description: Encrypts the file content in chunks using the public key
# Output: Encrypted data (bytes)
def encrypt_file_content(file_content, public_key, chunk_size=190):
    encrypted_chunks = []
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(encrypt_chunk, file_content[i:i + chunk_size], public_key)
                   for i in range(0, len(file_content), chunk_size)]
        
        for future in futures:
            encrypted_chunks.append(future.result())
    
    encrypted_data = b''.join(encrypted_chunks)
    return encrypted_data

# Function to decrypt data chunks
# Input: Encrypted chunk (bytes), private key
# Description: Decrypts a chunk of encrypted data using the private key and RSA decryption with OAEP padding
# Output: Decrypted chunk (bytes)
def decrypt_chunk(chunk, private_key):
    return private_key.decrypt(
        chunk,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Function to decrypt file content
# Input: Encrypted file content (bytes), private key, chunk size (int, optional)
# Description: Decrypts the file content in chunks using the private key
# Output: Decrypted data (bytes)
def decrypt_file_content(file_content, private_key, chunk_size=256):
    decrypted_chunks = []
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(decrypt_chunk, file_content[i:i + chunk_size], private_key)
                   for i in range(0, len(file_content), chunk_size)]
        
        for future in futures:
            decrypted_chunks.append(future.result())
    
    decrypted_data = b''.join(decrypted_chunks)
    return decrypted_data

# Function to calculate SHA-256 hash
# Input: File content (bytes)
# Description: Calculates the SHA-256 hash of the given file content
# Output: SHA-256 hash (hexadecimal string)
def calculate_sha256(file_content):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_content)
    return sha256_hash.hexdigest()

# Initialize Streamlit app
st.title("Secure File Transfer with RSA and Hashing")
st.subheader("Generating the Keys")

# Initialize session state for key generation
if "keys_generated" not in st.session_state:
    st.session_state.keys_generated = False

# Button to generate keys
if st.button("Generate the Keys"):
    st.session_state.message = generate_rsa_keys()
    st.session_state.keys_generated = True

# Display the result message and download buttons for keys
if st.session_state.keys_generated:
    st.text(st.session_state.message)

    # Download button for private key
    with open("private_key.pem", "rb") as private_file:
        st.download_button(
            label="Download Private Key",
            data=private_file,
            file_name="private_key.pem",
            mime="application/x-pem-file"
        )

    # Download button for public key
    with open("public_key.pem", "rb") as public_file:
        st.download_button(
            label="Download Public Key",
            data=public_file,
            file_name="public_key.pem",
            mime="application/x-pem-file"
        )

# File uploader for original document
st.text("\n\n\n")
uploaded_file = st.file_uploader("***Choose a document to encrypt***", type=["txt", "pdf", "docx", "png", "jpeg"])

if uploaded_file is not None:
    file_data = uploaded_file.read()
    original_file_name = uploaded_file.name
    original_file_extension = os.path.splitext(original_file_name)[1]
    
    # Calculate and display SHA-256 hash of the original file
    original_file_hash = calculate_sha256(file_data)
    st.text(f"SHA-256 Hash of Original File: {original_file_hash}")
    
    # Load public key
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Encrypt the file content
    encrypted_data = encrypt_file_content(file_data, public_key)

    # Download button for encrypted file
    st.download_button(
        label="Download Encrypted File",
        data=encrypted_data,
        file_name="encrypted_file.enc",
        mime="application/octet-stream"
    )

# File uploader for encrypted document and private key
st.text("\n\n\n")
uploaded_encrypted_file = st.file_uploader("***Choose an encrypted file to decrypt***", type=["enc"])
uploaded_private_key = st.file_uploader("***Choose your private key file***", type=["pem"])

if uploaded_encrypted_file is not None and uploaded_private_key is not None:
    encrypted_file_data = uploaded_encrypted_file.read()
    private_key_data = uploaded_private_key.read()
    
    # Load private key
    private_key = serialization.load_pem_private_key(private_key_data, password=None)

    # Decrypt the file content
    decrypted_data = decrypt_file_content(encrypted_file_data, private_key)
    
    # Calculate and display SHA-256 hash of the decrypted file
    decrypted_file_hash = calculate_sha256(decrypted_data)
    st.text(f"SHA-256 Hash of Decrypted File: {decrypted_file_hash}")
    
    # Compare hashes and display result
    if original_file_hash == decrypted_file_hash:
        st.text("Success: The decrypted file is identical to the original file.")
    else:
        st.text("Error: The decrypted file is corrupted!.")
    
    # Download button for decrypted file
    st.download_button(
        label="Download Decrypted File",
        data=decrypted_data,
        file_name=f"decrypted_file{original_file_extension}",
        mime="application/octet-stream"
    )
