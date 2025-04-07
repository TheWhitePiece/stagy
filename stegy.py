#!/usr/bin/env python
# coding: utf-8

import os
import json
import datetime
import hashlib
import numpy as np
import cv2
import wave
from typing import Optional

LOG_FILE = "steganography_logs.json"

USERS = {
    "admin": {
        "password_hash": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
        "role": "admin",
        "last_login": None
    },
    "user": {
        "password_hash": "04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb",
        "role": "user",
        "last_login": None
    }
}


def initialize_logs():
    """Ensure the log file exists."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w') as f:
            json.dump([], f)


def log_activity(username: str,
                 operation: str,
                 file_name: str,
                 status: str,
                 details: str = ""):
    """Append an entry to the JSON log."""
    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "operation": operation,
        "file": file_name,
        "status": status,
        "details": details
    }
    with open(LOG_FILE, 'r+', encoding='utf-8') as f:
        logs = json.load(f)
        logs.append(entry)
        f.seek(0)
        json.dump(logs, f, indent=4)


def hash_password(password: str) -> str:
    """SHA‑256 hash of a password."""
    return hashlib.sha256(password.encode()).hexdigest()


# ─── TEXT STEGANOGRAPHY ──────────────────────────────────────────────────────

def encode_text(cover_path: str,
                data: str,
                output_path: str,
                username: str) -> None:
    """Hide `data` inside the text at `cover_path`, write stego text to `output_path`."""
    # 1) build the binary payload
    bits = ""
    for ch in data:
        t = ord(ch)
        if 32 <= t <= 64:
            t2 = (t + 48) ^ 170
            bits += "0011" + format(t2, '08b')
        else:
            t2 = (t - 48) ^ 170
            bits += "0110" + format(t2, '08b')
    bits += "111111111111"  # terminator

    # 2) read cover words
    with open(cover_path, 'r', encoding='utf-8') as f:
        words = []
        for line in f:
            words.extend(line.split())

    # 3) map every 12 bits → zero‑width chars
    ZWC = {
        "00": "\u200C",
        "01": "\u202C",
        "11": "\u202D",
        "10": "\u200E"
    }

    with open(output_path, 'w', encoding='utf-8') as out:
        i = 0
        # embed in first len(bits)//12 words
        while i < len(bits):
            w = words[i // 12]
            chunk = bits[i:i+12]
            zwc = "".join(ZWC[chunk[j:j+2]] for j in range(0, 12, 2))
            out.write(w + zwc + " ")
            i += 12
        # copy remaining words
        for w in words[len(bits)//12:]:
            out.write(w + " ")

    log_activity(username, "text_encode", output_path,
                 "success", f"Encoded {len(data)} chars")


def decode_text(stego_path: str, username: str) -> str:
    """Extract hidden text from `stego_path` and return it."""
    ZWC_rev = {
        "\u200C": "00",
        "\u202C": "01",
        "\u202D": "11",
        "\u200E": "10"
    }
    bits = ""
    stop = False
    with open(stego_path, 'r', encoding='utf-8') as f:
        for line in f:
            if stop:
                break
            for w in line.split():
                seq = ""
                for ch in w:
                    if ch in ZWC_rev:
                        seq += ZWC_rev[ch]
                if seq == "111111111111":
                    stop = True
                    break
                bits += seq

    # decode every 12‑bit block
    decoded = ""
    for i in range(0, len(bits), 12):
        header = bits[i:i+4]
        body   = bits[i+4:i+12]
        val = int(body, 2) ^ 170
        if header == "0011":
            decoded += chr(val - 48)
        elif header == "0110":
            decoded += chr(val + 48)

    log_activity(username, "text_decode", stego_path,
                 "success", f"Decoded {len(decoded)} chars")
    return decoded


# ─── IMAGE STEGANOGRAPHY ─────────────────────────────────────────────────────

def msgtobinary(x):
    """Convert str, int, bytes, or ndarray to binary string(s)."""
    if isinstance(x, str):
        return "".join(format(ord(c), '08b') for c in x)
    elif isinstance(x, (bytes, bytearray, np.ndarray)):
        return [format(b, '08b') for b in x]
    elif isinstance(x, (int, np.integer)):
        return format(int(x), '08b')
    else:
        raise TypeError("Unsupported type for msgtobinary")


def encode_image(input_path: str,
                 data: str,
                 output_path: str,
                 username: str) -> None:
    """Hide `data` inside the image at `input_path`, write to `output_path`."""
    img = cv2.imread(input_path)
    if img is None:
        raise FileNotFoundError(f"Cover image not found: {input_path}")

    payload = data + "*^*^*"
    bin_data = msgtobinary(payload)
    total_bits = len(bin_data)
    max_bytes = (img.shape[0] * img.shape[1] * 3) // 8
    if len(payload) > max_bytes:
        log_activity(username, "image_encode", output_path,
                     "failed", "Insufficient capacity")
        raise ValueError("Insufficient capacity in image")

    idx = 0
    for row in img:
        for pix in row:
            for c in range(3):
                if idx < total_bits:
                    bit = bin_data[idx]
                    orig = format(int(pix[c]), '08b')
                    pix[c] = int(orig[:-1] + bit, 2)
                    idx += 1
            if idx >= total_bits:
                break
        if idx >= total_bits:
            break

    cv2.imwrite(output_path, img)
    log_activity(username, "image_encode", output_path,
                 "success", f"Encoded {len(data)} chars")


def decode_image(input_path: str, username: str) -> str:
    """Extract hidden text from the image at `input_path`."""
    img = cv2.imread(input_path)
    if img is None:
        raise FileNotFoundError(f"Stego image not found: {input_path}")

    bits = ""
    for row in img:
        for pix in row:
            for c in range(3):
                bits += format(int(pix[c]), '08b')[-1]
            # check terminator
            if len(bits) >= 8:
                chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
                txt = "".join(chr(int(b,2)) for b in chars)
                if txt.endswith("*^*^*"):
                    result = txt[:-5]
                    log_activity(username, "image_decode", input_path,
                                 "success", f"Decoded {len(result)} chars")
                    return result
    # if not found, return what we have
    return ""


# ─── AUDIO STEGANOGRAPHY ─────────────────────────────────────────────────────

def encode_audio(input_path: str,
                 data: str,
                 output_path: str,
                 username: str) -> None:
    """Hide `data` inside the WAV at `input_path`, write to `output_path`."""
    song = wave.open(input_path, 'rb')
    params = song.getparams()
    frames = song.readframes(song.getnframes())
    song.close()

    frame_bytes = bytearray(frames)
    payload = data + "*^*^*"
    bits = []
    for ch in payload:
        bits.extend(int(b) for b in format(ord(ch), '08b'))

    j = 0
    for bit in bits:
        byte = frame_bytes[j]
        bstr = format(byte, '08b')
        # embed in LSB or second‑LSB
        if bstr[-4] == str(bit):
            frame_bytes[j] = byte & 0b11111101
        else:
            frame_bytes[j] = (byte & 0b11111101) | 0b10
            frame_bytes[j] = (frame_bytes[j] & 0b11111110) | bit
        j += 1

    with wave.open(output_path, 'wb') as fd:
        fd.setparams(params)
        fd.writeframes(bytes(frame_bytes))

    log_activity(username, "audio_encode", output_path,
                 "success", f"Encoded {len(data)} chars")


def decode_audio(input_path: str, username: str) -> str:
    """Extract hidden text from the WAV at `input_path`."""
    song = wave.open(input_path, 'rb')
    frames = song.readframes(song.getnframes())
    song.close()

    frame_bytes = bytearray(frames)
    extracted = ""
    for b in frame_bytes:
        bstr = format(b, '08b')
        if bstr[-2] == '0':
            extracted += bstr[-4]
        else:
            extracted += bstr[-1]
        # every 8 bits, try decode
        if len(extracted) % 8 == 0:
            chars = [extracted[i:i+8] for i in range(0, len(extracted), 8)]
            txt = "".join(chr(int(c,2)) for c in chars)
            if txt.endswith("*^*^*"):
                result = txt[:-5]
                log_activity(username, "audio_decode", input_path,
                             "success", f"Decoded {len(result)} chars")
                return result
    return ""


# ─── VIDEO STEGANOGRAPHY ─────────────────────────────────────────────────────

def KSA(key):
    """Key-scheduling algorithm (RC4)."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def PRGA(S, n):
    """Pseudo-random generation algorithm (RC4)."""
    i = j = 0
    out = []
    while n > 0:
        n -= 1
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) % 256])
    return out


def preparing_key_array(s: str):
    return [ord(c) for c in s]


def encryption(plaintext: str, key_str: str) -> str:
    key = preparing_key_array(key_str)
    S = KSA(key)
    keystream = np.array(PRGA(S, len(plaintext)))
    plain_arr = np.array([ord(c) for c in plaintext])
    cipher = keystream ^ plain_arr
    return "".join(chr(c) for c in cipher)


def decryption(ciphertext: str, key_str: str) -> str:
    key = preparing_key_array(key_str)
    S = KSA(key)
    keystream = np.array(PRGA(S, len(ciphertext)))
    cipher_arr = np.array([ord(c) for c in ciphertext])
    decoded = keystream ^ cipher_arr
    return "".join(chr(c) for c in decoded)


def encode_video(input_path: str,
                 data: str,
                 frame_no: int,
                 output_path: str,
                 username: str,
                 key: Optional[str] = None) -> None:
    """Hide `data` in frame `frame_no` of the video at `input_path`."""
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise FileNotFoundError(f"Cover video not found: {input_path}")

    # optionally encrypt
    payload = data
    if key:
        payload = encryption(data, key)
    payload += "*^*^*"
    bits = msgtobinary(payload)

    # gather video specs
    fps    = cap.get(cv2.CAP_PROP_FPS)
    width  = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out    = cv2.VideoWriter(output_path, fourcc, fps, (width, height))

    idx = 0
    fidx = 0
    embedded = False

    while True:
        ret, frame = cap.read()
        if not ret:
            break
        fidx += 1
        if fidx == frame_no:
            # embed here
            for row in frame:
                for pix in row:
                    for c in range(3):
                        if idx < len(bits):
                            bit = bits[idx]
                            orig = format(int(pix[c]), '08b')
                            pix[c] = int(orig[:-1] + bit, 2)
                            idx += 1
                    if idx >= len(bits):
                        break
                if idx >= len(bits):
                    break
            embedded = True
        out.write(frame)

    cap.release()
    out.release()

    if not embedded:
        raise ValueError(f"Frame {frame_no} out of range")

    log_activity(username, "video_encode", output_path,
                 "success", f"Encoded at frame {frame_no}")


def decode_video(input_path: str,
                 frame_no: int,
                 username: str,
                 key: Optional[str] = None) -> str:
    """Extract hidden text from frame `frame_no` of the video at `input_path`."""
    cap = cv2.VideoCapture(input_path)
    if not cap.isOpened():
        raise FileNotFoundError(f"Stego video not found: {input_path}")

    fidx = 0
    extracted = ""

    while True:
        ret, frame = cap.read()
        if not ret:
            break
        fidx += 1
        if fidx == frame_no:
            # extract all bits from this frame
            bits = ""
            for row in frame:
                for pix in row:
                    for c in range(3):
                        bits += format(int(pix[c]), '08b')[-1]
            # to text
            bytes_ = [bits[i:i+8] for i in range(0, len(bits), 8)]
            txt = "".join(chr(int(b,2)) for b in bytes_)
            if "*^*^*" in txt:
                extracted = txt.split("*^*^*")[0]
            break

    cap.release()

    if key and extracted:
        extracted = decryption(extracted, key)

    log_activity(username, "video_decode", input_path,
                 "success", f"Decoded from frame {frame_no}")
    return extracted
