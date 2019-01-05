import getopt
import sys
import binascii
import struct
import hashlib

modulus_type3 = 0xe087c9b91aa2e0900f335a6fa161c6621a5a04e3bb75104d696cd29614f085f8e54820535fd316adb2ae6d2294aa9ee809f1555ce841a8fc1495517641ec6d92e97d6d457047e3341491ab0919cebee1f249d5d6899929016271f7f9bd89e24a3c60b977a6d12048d19069484e9c95839c2bd56d899ff74db27d79d2f8d894f3724dfe1a119c4a2991d80544d3a1f1c773cea38fdf0650a2ae5d2689e9a9bfb8828f06ec945bba44fab3573949613a0e7bbd685fc13e3b66c940cd2cb2ae4e254c12022df95be135b5aa70148c12278529090171f80c18ed3f3c3eca9fca3d1cbba5134e3045590eac1c433adfec58f520f2714b3d95f257f8db24e0d8acd5ffL

modulus_type2 = 0xe0a81d0d55bea0c79052e21886a34c22456d09f03daba84f2808e957b9e534034113593f023076b847588b7eb2873fab06317c49273c8662f869f9354f53ba6ca2d0cd061ce1fca5124fb84f3748af5d8666a091c8b7fb03571a5fb24ccfbba070ebb77e76937d21f3344e06e6c982c7c22b9ad1e3310952f18b5273ec6f7d659d4b8eb99b8a06502b3799efcca9ffec5236c93867547e74ac1f745b81103efba271aaeba0f4e44819423d6ff0eb8f335e985c18a3a677ef2c144f63d8fd1e507ceabe1ee6b7f8375d396752c30a3d845e58db3f16af596d0b20599ad81900079f003df1d87d5fcba05858fdf08123c8dfdf6bb4f0a27c4f7eda5587c34f47cbL


# code to calculate a STM32F103 compatible CRC taken from
# https://stackoverflow.com/questions/36483334/make-crc-on-stm32-match-with-software-implementation/

custom_crc_table = {}
poly = 0x04C11DB7

def generate_crc32_table(_poly):

    global custom_crc_table

    for i in range(256):
        c = i << 24

        for j in range(8):
            c = (c << 1) ^ _poly if (c & 0x80000000) else c << 1

        custom_crc_table[i] = c & 0xffffffff

def crc32_stm(bytes_arr):

    length = len(bytes_arr)
    crc = 0xffffffff

    k = 0
    while length >= 4:

        v = ((bytes_arr[k] << 24) & 0xFF000000) | ((bytes_arr[k+1] << 16) & 0xFF0000) | \
        ((bytes_arr[k+2] << 8) & 0xFF00) | (bytes_arr[k+3] & 0xFF)

        crc = ((crc << 8) & 0xffffffff) ^ custom_crc_table[0xFF & ((crc >> 24) ^ v)]
        crc = ((crc << 8) & 0xffffffff) ^ custom_crc_table[0xFF & ((crc >> 24) ^ (v >> 8))]
        crc = ((crc << 8) & 0xffffffff) ^ custom_crc_table[0xFF & ((crc >> 24) ^ (v >> 16))]
        crc = ((crc << 8) & 0xffffffff) ^ custom_crc_table[0xFF & ((crc >> 24) ^ (v >> 24))]

        k += 4
        length -= 4

    if length > 0:
        v = 0

        for i in range(length):
            v |= (bytes_arr[k+i] << 24-i*8)

        if length == 1:
            v &= 0xFF000000

        elif length == 2:
            v &= 0xFFFF0000

        elif length == 3:
            v &= 0xFFFFFF00

        crc = (( crc << 8 ) & 0xffffffff) ^ custom_crc_table[0xFF & ( (crc >> 24) ^ (v ) )]
        crc = (( crc << 8 ) & 0xffffffff) ^ custom_crc_table[0xFF & ( (crc >> 24) ^ (v >> 8) )]
        crc = (( crc << 8 ) & 0xffffffff) ^ custom_crc_table[0xFF & ( (crc >> 24) ^ (v >> 16) )]
        crc = (( crc << 8 ) & 0xffffffff) ^ custom_crc_table[0xFF & ( (crc >> 24) ^ (v >> 24) )]


    return crc

CRC_STANDARD=1
CRC_STM32=2

def crc32(data):
    if CRC == CRC_STANDARD:
        standard_crc = binascii.crc32(data)
        standard_crc = standard_crc & 0xFFFFFFFF
        return standard_crc
    elif CRC == CRC_STM32:
        b = bytearray()
        b.extend(data)
        crc = crc32_stm(b)
        return crc
    
    output(1, "[-] ILLEGAL CRC SELECTED")

# initialize our custom crc32 table
generate_crc32_table(poly)


# code of modexp taken from
# https://stackoverflow.com/questions/5486204/fast-modulo-calculations-in-python-and-ruby

def modexp ( g, u, p ):
   """computes s = (g ^ u) mod p
      args are base, exponent, modulus
      (see Bruce Schneier's book, _Applied Cryptography_ p. 244)"""
   s = 1
   while u != 0:
      if u & 1:
         s = (s * g)%p
      u >>= 1
      g = (g * g)%p;
   return s


def check_padding(sig):
    
    sha256_tail = "\x00\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"

    PAD_LEN=256-32
    TAIL_LEN=len(sha256_tail)
    
    # generate valid padding string
    padding = "0x1" + "ff" * (PAD_LEN - TAIL_LEN - 2) + binascii.hexlify(sha256_tail)
    
    # convert to signature to hex string and verify
    hex_sig = hex(sig)    
    if hex_sig.startswith(padding) and (len(hex_sig) - len(padding) == 32*2+1):
        return True
    
    return False
    
    
def usage():
    print "usage information"

output_level = 1

AFU_ERROR_MAGIC_MISMATCH=16
AFU_ERROR_MAGIC2_MISMATCH=17
AFU_ERROR_HEADER_CRC_MISMATCH=18

AFU_ERROR_DATA_CRC_MISMATCH=22

AFU_ERROR_INCOMPATIBLE_PRODUCT_ID=23

AFU_ERROR_DIGEST_MISMATCH=113

AFU_ERROR_SIGNATURE_MAGIC_MISMATCH=115
AFU_ERROR_SIGNATURE_MAGIC2_MISMATCH=116

AFU_ERROR_UNSUPPORTED_DIGEST=117
AFU_ERROR_UNSUPPORTED_SIGNATURE=118


def output(level, output_str):
    
    global output_level
    
    if level >= output_level:
        print "%s" % output_str

firmwaretypes = {}
firmwaretypes[0xc0] = "KeyCal"
firmwaretypes[0xc1] = "MTCal"
firmwaretypes[0xc2] = "ForceCal"
firmwaretypes[0xc3] = "ActCal"
firmwaretypes[0xc4] = "AccelCal"
firmwaretypes[0xc5] = "AudioCal"
firmwaretypes[0xa0] = "VibeWaveform"
firmwaretypes[0xb0] = "BootLoader"
firmwaretypes[0x20] = "MTFW"
firmwaretypes[0x30] = "RadioFW"
firmwaretypes[0x01] = "STFW"
firmwaretypes[0x31] = "RadioDiags"
firmwaretypes[0x40] = "AudioFW"
firmwaretypes[0x41] = "AudioCalFW"
firmwaretypes[0x50] = "ChargerFW"
firmwaretypes[0x60] = "AccelAlgs"


def firmwaretype(type):
    
    global firmwaretypes
    
    if firmwaretypes.has_key(type):
        return firmwaretypes[type]
    return "unknown"

def check(filename):
    
    global CRC
    
    f = open(filename, "rb")
    
    # read in the AFU header
    f.seek(0)
    AFU_header_data = f.read(20)
    
    (magic, unknown1, fw_type, fw_ver, fw_len, fw_crc, product_id, hw_rev_id) = struct.unpack("<HHHHIIHH", AFU_header_data)
    
    # Check Magic values
    
    if magic != 0xA2C7:
        
        output(1, "[-] AFU magic missing expected 0xA2C7 but got 0x%x - not an AFU file" % magic)
        
        return AFU_ERROR_MAGIC_MISMATCH
    if unknown1 != 256:
        output(1, "[-] AFU magic missing expected 0xA2C7 0x0100 but got 0xA2C7 0x%x - not an AFU file" % magic)
        
        return AFU_ERROR_MAGIC2_MISMATCH

    output(1, "[+] AFU magic matches")

    # Check product id

    # user standard CRC by default
    CRC=CRC_STANDARD

    if product_id == 0x222 or product_id == 0x312:
        
        output(1, "[+] AFU for Apple Pencil")
        CRC=CRC_STM32
        
    elif product_id == 0x266:
        
        output(1, "[+] AFU for Sire Remote 1")        
        CRC=CRC_STM32

    elif product_id == 0x14c:
        
        output(1, "[+] AFU for Apple Pencil 2")        

    elif product_id == 0x268:
        
        output(1, "[+] AFU for Smart Keyboard 12.9\"")        
        
    elif product_id == 0x26a:
        
        output(1, "[+] AFU for Smart Keyboard 9.7\"")        
    
    elif product_id == 0x26b:
        
        output(1, "[+] AFU for Smart Keyboard 10.5\"")        
    
    elif product_id == 0x26d:
        
        output(1, "[+] AFU for Siri Remote 2")        
    
    elif product_id == 0x292:
        
        output(1, "[+] AFU for Smart Keyboard Folio 11\"")        
    
    elif product_id == 0x293:
        
        output(1, "[+] AFU for Smart Keyboard Folio 12.9\"")        
    
    else:
        output(1, "[-] AFU for unknown product id 0x%x" % product_id)
        #return AFU_ERROR_INCOMPATIBLE_PRODUCT_ID

    output(2, "[+] AFU Firmware Type: 0x%x (%s)" % (fw_type, firmwaretype(fw_type)))
    output(2, "[+] AFU Harware Revision: %d" % hw_rev_id)

    if CRC == CRC_STANDARD:
        crc_algorithm = "standard"
    elif CRC == CRC_STM32:
        crc_algorithm = "stm32"
    else:
        crc_algorithm = "unknown"

    output(1, "[!] CRC algorithm: %s" % crc_algorithm)

    f.seek(0)
    full_header_data = f.read(124)
    crc = crc32(full_header_data)
    
    header_crc_data = f.read(4)
    (header_crc,) = struct.unpack("<I", header_crc_data)
    
    if header_crc == crc:
        output(1, "[+] AFU header CRC matches")
    else:
        output(1, "[-] AFU header CRC mismatch (expected 0x%x but got 0x%x)" % (header_crc, crc))
        #return AFU_ERROR_HEADER_CRC_MISMATCH

    f.seek(0x80)
    full_data = f.read(fw_len)
    crc = crc32(full_data)
    
    if fw_crc == crc:
        output(1, "[+] AFU data CRC matches")
    else:
        output(1, "[-] AFU data CRC mismatch (expected 0x%x but got 0x%x)" % (fw_crc, crc))
        #return AFU_ERROR_DATA_CRC_MISMATCH
    
    # verify AFU signature header
    f.seek(0x20)
    AFU_signature_header_data = f.read(24)
    
    (sig_magic, unknown1, unknown2, digest_type, digest_len, digest_offset, sig_type, sig_len, sig_offset) = struct.unpack("<IHHHHIHHI", AFU_signature_header_data)
    
    # check content of extended signature
    if sig_magic != 0x61E34724:
        return AFU_ERROR_SIGNATURE_MAGIC_MISMATCH
        
    if unknown1 != 0x100:
        output(1, "[-] error in AFU signature header (expected: 0x61E34724 0x0100 but got: expected: 0x61E34724 0x%x)" % unkown1)
        return AFU_ERROR_SIGNATURE_MAGIC_MISMATCH
    
    if digest_len != 32 or digest_type != 1:
        output(1, "[-] unsupported AFU signature (type: %d, len: %d)" % (digest_type, digest_len))
        return AFU_ERROR_UNSUPPORTED_DIGEST
    
    if (sig_type != 2 and sig_type != 3) or sig_len != 256:
        output(1, "[-] unsupported AFU signature (type: %d, len: %d)" % (sig_type, sig_len))
        return AFU_ERROR_UNSUPPORTED_SIGNATURE
    
    f.seek(digest_offset)
    AFU_digest = f.read(digest_len)

    # construct full data for SHA256
    full_data = full_header_data + header_crc_data + full_data
    
    s256 = hashlib.sha256()
    s256.update(full_data)
    digest = s256.digest()
    
    if digest == AFU_digest:
        output(1, "[+] AFU sha256 digest matches")
    else:
        output(1, "[-] AFU sha256 digest mismatch (expected: %s but got: %s)" % (binascii.hexlify(AFU_digest), binascii.hexlify(digest)))
        return AFU_ERROR_DIGEST_MISMATCH
    
    # now we can check the RSA signature
    f.seek(sig_offset)
    sig_data = f.read(sig_len)
    hex_signature = binascii.hexlify(sig_data)
    signature = long(hex_signature, 16)
    
    # select right key
    if sig_type == 3:
        modulus = modulus_type3
    elif sig_type == 2:
        modulus = modulus_type2
    else:
        output(1, "[-] AFU signature of unsupported type: %d" % sig_type)
    
    output(1, "[+] AFU signature type: %d" % sig_type)
    
    # now decrypt the signature
    decrypted_signature = modexp(signature, 0x10001, modulus)
    
    padding_okay = check_padding(decrypted_signature)
    
    if padding_okay and hex(decrypted_signature).endswith(binascii.hexlify(digest) + "L"):
        output(1, "[+] AFU RSA2048 signature matches")
    else:
        if padding_okay:
            output(1, "[-] AFU RSA2048 signature mismatch (padding: pass, digest: fail)")
        else:
            output(1, "[-] AFU RSA2048 signature mismatch (padding: fail, digest: pass)")
    
            print ""
            print "!!! FOR DEBUGGING PURPOSES WE OUTPUT DIGEST AND DECRYPTED SIGNATURE"
            print binascii.hexlify(digest)
            print hex(decrypted_signature)


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", [])
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    for filename in args:
        print ""
        print "[+] Checking AFU file %s" % filename
        check(filename)


if __name__ == "__main__":
    main()