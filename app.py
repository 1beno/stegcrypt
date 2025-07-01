from flask import Flask, render_template, request, redirect, send_file, flash
from PIL import Image
import os
import base64

app = Flask(__name__)
# Kunci rahasia untuk sesi Flask
app.secret_key = 'my-secret-key'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ==============================================================================
# IMPLEMENTASI AES-128 (desain RIJNDAEL)
# ==============================================================================

# Konstanta-konstanta yang digunakan dalam AES
S_BOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)

INV_S_BOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
)

RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
)

class AESRijndael:
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Kunci harus 16 byte (128 bit).")
        self.key = key
        self.n_rounds = 10
        self._round_keys = self._expand_key(self.key)

    def _expand_key(self, master_key):
        key_columns = [list(master_key[i:i+4]) for i in range(0, 16, 4)]
        i = 1
        while len(key_columns) < 4 * (self.n_rounds + 1):
            word = list(key_columns[-1])
            if len(key_columns) % 4 == 0:
                word.append(word.pop(0))
                word = [S_BOX[b] for b in word]
                word[0] ^= RCON[i]
                i += 1
            prev_word = key_columns[-4]
            new_word = [prev_word[b] ^ word[b] for b in range(4)]
            key_columns.append(new_word)
        return [sum(key_columns[i:i+4], []) for i in range(0, len(key_columns), 4)]

    def _sub_bytes(self, state, inverse=False):
        box = INV_S_BOX if inverse else S_BOX
        for i in range(16):
            state[i] = box[state[i]]
        return state

    def _shift_rows(self, state, inverse=False):
        if not inverse:
            state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
            state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
            state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
        else:
            state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
            state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
            state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
        return state

    def _gf_mult(self, a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            is_high_bit_set = a & 0x80
            a <<= 1
            if is_high_bit_set:
                a ^= 0x11b
            b >>= 1
        return p & 0xff

    def _mix_columns(self, state, inverse=False):
        for i in range(4):
            col = state[i*4 : i*4 + 4]
            if not inverse:
                c0 = self._gf_mult(col[0], 2) ^ self._gf_mult(col[1], 3) ^ col[2] ^ col[3]
                c1 = col[0] ^ self._gf_mult(col[1], 2) ^ self._gf_mult(col[2], 3) ^ col[3]
                c2 = col[0] ^ col[1] ^ self._gf_mult(col[2], 2) ^ self._gf_mult(col[3], 3)
                c3 = self._gf_mult(col[0], 3) ^ col[1] ^ col[2] ^ self._gf_mult(col[3], 2)
            else:
                c0 = self._gf_mult(col[0], 14) ^ self._gf_mult(col[1], 11) ^ self._gf_mult(col[2], 13) ^ self._gf_mult(col[3], 9)
                c1 = self._gf_mult(col[0], 9) ^ self._gf_mult(col[1], 14) ^ self._gf_mult(col[2], 11) ^ self._gf_mult(col[3], 13)
                c2 = self._gf_mult(col[0], 13) ^ self._gf_mult(col[1], 9) ^ self._gf_mult(col[2], 14) ^ self._gf_mult(col[3], 11)
                c3 = self._gf_mult(col[0], 11) ^ self._gf_mult(col[1], 13) ^ self._gf_mult(col[2], 9) ^ self._gf_mult(col[3], 14)
            state[i*4:i*4+4] = [c0, c1, c2, c3]
        return state

    def _add_round_key(self, state, round_key):
        for i in range(16):
            state[i] ^= round_key[i]
        return state

    def encrypt_block(self, plaintext):
        if len(plaintext) != 16:
            raise ValueError("Plaintext harus 16 byte.")
        state = list(plaintext)
        state = self._add_round_key(state, self._round_keys[0])
        for i in range(1, self.n_rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self._round_keys[i])
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self._round_keys[self.n_rounds])
        return bytes(state)

    def decrypt_block(self, ciphertext):
        if len(ciphertext) != 16:
            raise ValueError("Ciphertext harus 16 byte.")
        state = list(ciphertext)
        state = self._add_round_key(state, self._round_keys[self.n_rounds])
        for i in range(self.n_rounds - 1, 0, -1):
            state = self._shift_rows(state, inverse=True)
            state = self._sub_bytes(state, inverse=True)
            state = self._add_round_key(state, self._round_keys[i])
            state = self._mix_columns(state, inverse=True)
        state = self._shift_rows(state, inverse=True)
        state = self._sub_bytes(state, inverse=True)
        state = self._add_round_key(state, self._round_keys[0])
        return bytes(state)


# === FUNGSI HELPER UNTUK ENKRIPSI/DEKRIPSI AES ===
# Blok AES berukuran 16 byte
BLOCK_SIZE = 16

def _pad(data):
    """Menambahkan padding PKCS#7 ke data."""
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def _unpad(data):
    """Menghapus padding PKCS#7 dari data."""
    padding_len = data[-1]
    if padding_len > BLOCK_SIZE or padding_len == 0:
        raise ValueError("Padding tidak valid.")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Padding tidak valid.")
    return data[:-padding_len]

def _prepare_key(key_str):
    """Mengubah string kunci menjadi kunci 16-byte."""
    key_bytes = key_str.encode('utf-8')
    if len(key_bytes) > 16:
        # Potong jika terlalu panjang
        return key_bytes[:16]
    else:
        # Tambahkan padding jika terlalu pendek
        return key_bytes.ljust(16, b'\0')

def aes_encrypt(message, key):
    """
    Enkripsi pesan menggunakan AES dengan mode ECB.
    """
    # Siapkan kunci dan pesan
    key_bytes = _prepare_key(key)
    message_bytes = message.encode('utf-8')
    padded_message = _pad(message_bytes)
    
    # Buat instance AES
    aes = AESRijndael(key_bytes)
    
    encrypted_bytes = b''
    # Enkripsi per blok
    for i in range(0, len(padded_message), BLOCK_SIZE):
        block = padded_message[i:i+BLOCK_SIZE]
        encrypted_block = aes.encrypt_block(block)
        encrypted_bytes += encrypted_block
        
    # Kembalikan dalam format base64
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def aes_decrypt(ciphertext, key):
    """
    Dekripsi pesan AES (mode ECB) dari format base64.
    """
    # Siapkan kunci
    key_bytes = _prepare_key(key)
    
    # Dekode dari base64
    try:
        encrypted_bytes = base64.b64decode(ciphertext)
    except (base64.binascii.Error, ValueError):
        raise ValueError("Ciphertext tidak valid (bukan base64).")
        
    if len(encrypted_bytes) % BLOCK_SIZE != 0:
        raise ValueError("Panjang ciphertext tidak valid.")

    # Buat instance AES
    aes = AESRijndael(key_bytes)
    
    decrypted_padded_bytes = b''
    # Dekripsi per blok
    for i in range(0, len(encrypted_bytes), BLOCK_SIZE):
        block = encrypted_bytes[i:i+BLOCK_SIZE]
        decrypted_block = aes.decrypt_block(block)
        decrypted_padded_bytes += decrypted_block
        
    # Hapus padding dan kembalikan sebagai string
    try:
        decrypted_bytes = _unpad(decrypted_padded_bytes)
        return decrypted_bytes.decode('utf-8')
    except (ValueError, UnicodeDecodeError) as e:
        # Jika unpadding gagal atau hasil bukan UTF-8 valid, kemungkinan kunci salah
        raise ValueError(f"Gagal mendekripsi: {e}")


# ==============================================================================
# LOGIKA STEGANOGRAFI
# ==============================================================================

def text_to_bin(text):
    """Mengubah teks menjadi representasi biner."""
    return ''.join(format(ord(c), '08b') for c in text)

def bin_to_text(binary):
    """Mengubah representasi biner kembali menjadi teks."""
    if len(binary) % 8 != 0:
        binary = binary[:-(len(binary) % 8)]
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join([chr(int(b, 2)) for b in chars])

def encode_message(img, message):
    """Menyisipkan pesan biner ke dalam piksel gambar."""
    binary_msg = text_to_bin(message) + '1111111111111110'  # Penanda akhir
    pixels = list(img.getdata())
    
    if len(binary_msg) > len(pixels) * 3:
        return None # Pesan terlalu besar

    encoded_pixels = []
    data_index = 0

    for pixel in pixels:
        r, g, b = pixel
        if data_index < len(binary_msg):
            r = (r & ~1) | int(binary_msg[data_index])
            data_index += 1
        if data_index < len(binary_msg):
            g = (g & ~1) | int(binary_msg[data_index])
            data_index += 1
        if data_index < len(binary_msg):
            b = (b & ~1) | int(binary_msg[data_index])
            data_index += 1
        encoded_pixels.append((r, g, b))

    img.putdata(encoded_pixels)
    return img

def decode_message(img):
    """Mengekstrak pesan biner dari piksel gambar."""
    pixels = list(img.getdata())
    binary_data = ''
    for pixel in pixels:
        for color in pixel[:3]:
            binary_data += str(color & 1)

    end_marker = '1111111111111110'
    end_index = binary_data.find(end_marker)
    if end_index == -1:
        return None # Penanda akhir tidak ditemukan

    return bin_to_text(binary_data[:end_index])


# ==============================================================================
# FLASK ROUTES 
# ==============================================================================

@app.route('/')
def index():
    """Menampilkan halaman utama."""
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt_route():
    """Menangani proses enkripsi."""
    if request.method == 'POST':
        image = request.files.get('image')
        message = request.form.get('message')
        key = request.form.get('key')

        if not image or not message or not key:
            flash('Semua input wajib diisi!', 'error')
            return redirect(request.url)

        if not image.filename.lower().endswith('.png'):
            flash('File harus berformat .png', 'error')
            return redirect(request.url)
        
        img = Image.open(image).convert('RGB')
        
        # Enkripsi pesan sebelum disisipkan menggunakan AES yang baru
        encrypted_message = aes_encrypt(message, key)
        
        encoded_img = encode_message(img.copy(), encrypted_message)

        if encoded_img is None:
            flash('Pesan terlalu panjang untuk disisipkan pada gambar ini.', 'error')
            return redirect(request.url)

        filename = 'encoded.png'
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        encoded_img.save(output_path)

        flash('Pesan berhasil dienkripsi dan disisipkan!', 'success')
        return render_template('encrypt.html', filename=filename)

    return render_template('encrypt.html')

@app.route('/download/<filename>')
def download_file(filename):
    """Menyediakan file untuk diunduh."""
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    else:
        flash('File tidak ditemukan.', 'error')
        return redirect('/')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt_route():
    """Menangani proses dekripsi."""
    if request.method == 'POST':
        image = request.files.get('image')
        key = request.form.get('key')

        if not image or not key:
            flash('Gambar dan kunci wajib diisi!', 'error')
            return redirect(request.url)

        if not image.filename.lower().endswith('.png'):
            flash('File harus berformat .png', 'error')
            return redirect(request.url)
        
        img = Image.open(image).convert('RGB')
        
        # Ekstrak pesan terenkripsi (dalam format base64) dari gambar
        encrypted_message = decode_message(img)

        if encrypted_message is None:
            flash('Tidak ditemukan pesan rahasia!', 'error')
            return redirect(request.url)

        try:
            # Dekripsi pesan menggunakan AES yang baru
            decrypted_message = aes_decrypt(encrypted_message, key)
            flash('Pesan berhasil didekripsi!', 'success')
            return render_template('decrypt.html', result=decrypted_message)
        except ValueError as e:
            # Tangkap error jika dekripsi gagal (kemungkinan kunci salah)
            flash(f'Gagal mendekripsi pesan. Cek kembali kunci Anda! ({e})', 'error')
            return redirect(request.url)
            
    return render_template('decrypt.html')

if __name__ == '__main__':
    app.run(debug=True)
