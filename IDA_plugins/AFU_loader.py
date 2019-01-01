import idaapi
import struct
import ida_idp
import idc
import ida_nalt

SRAM_BASE = 0x20000000
SRAM_SIZE = 128*1024
EXCEPTION_PREFIX = "_exception"

exception_table = {}
exception_table[1] = "RESET"
exception_table[2] = "NMI"
exception_table[3] = "HARDFAULT"
exception_table[4] = "MEMFAULT"
exception_table[5] = "BUSFAULT"
exception_table[6] = "USAGEFAULT"
exception_table[7] = "RESERVED"
exception_table[8] = "RESERVED"
exception_table[9] = "RESERVED"
exception_table[10] = "RESERVED"
exception_table[11] = "SVC"
exception_table[12] = "DEBUG"
exception_table[13] = "RESERVED"
exception_table[14] = "PENDSV"
exception_table[15] = "SYSTICK"
for i in range(16,255):
	exception_table[i] = "IRQ%d" % (i-16)

def register_structs():
	
	str_afu_header = """

	struct afu_header {
		unsigned short magic;
		unsigned short unk_0x100;
		unsigned short fw_type;
		unsigned short fw_version;
		unsigned int fw_len;
		unsigned int fw_crc;
		unsigned short product_id;
		unsigned short hw_revision_id;
	};

	"""
	
	str_afu_sig_header = """

	struct afu_sig_header {
		unsigned int magic;
		unsigned short unk_0x100;
		unsigned short unk_0x120;
		unsigned short digest_type; // guess 1 sha256?
		unsigned short digest_len;
		unsigned int digest_offs;
		unsigned short sig_type;
		unsigned short sig_len;
		unsigned int sig_offs;
	};

	"""

	str_afu_pers_header = """

	struct afu_pers_header {
		unsigned int magic;
		unsigned short unk_0x100;
		unsigned char uniqueid[12];
		unsigned char reserved[0x1c-0x12];
		unsigned int flags;
	};

	"""

	str_afu_full_header = """

	struct afu_full_header {
		struct afu_header header;
		unsigned char reserved1[0x20-0x14];
		struct afu_sig_header sig_header;
		unsigned char reserved2[0x40-0x38];
		struct afu_pers_header pers_header;
		unsigned char reserved3[0x7c-0x60];
		unsigned int header_crc;
	};

	"""
	
	sid = idc.get_struc_id("afu_header")
	if sid != -1:
		idc.del_struc(sid)
	
	r = idc.SetLocalType(-1, str_afu_header, 0)
		
	r = idc.import_type(-1, "afu_header")
		
	sid = idc.get_struc_id("afu_sig_header")
	if sid != -1:
		idc.del_struc(sid)
	
	r = idc.SetLocalType(-1, str_afu_sig_header, 0)
		
	r = idc.import_type(-1, "afu_sig_header")
	
	sid = idc.get_struc_id("afu_pers_header")
	if sid != -1:
		idc.del_struc(sid)
	
	r = idc.SetLocalType(-1, str_afu_pers_header, 0)
		
	r = idc.import_type(-1, "afu_pers_header")
	
	sid = idc.get_struc_id("afu_full_header")
	if sid != -1:
		idc.del_struc(sid)
	
	r = idc.SetLocalType(-1, str_afu_full_header, 0)
		
	r = idc.import_type(-1, "afu_full_header")

def accept_file(li, filename):
	
	li.seek(0)
	data = li.read(0x14)
	(magic, xxx1, fw_type, fw_ver, fw_len, unk1, product_id, hw_rev_id) = struct.unpack("<HHHHIIHH", data)

	if magic != 0xa2c7:
		return 0
		
	# check if firmware type is kAUTypeSTFW
	if fw_type != 1:
		return 0
	
	if product_id == 0x312:
		device_type = "Apple Pencil"
	elif product_id == 0x268:
		device_type = "Smart Keyboard 12.9\""
	elif product_id == 0x26A:
		device_type = "Smart Keyboard 9.7\""
	elif product_id == 0x26B:
		device_type = "Smart Keyboard 10.5\""
	elif product_id == 0x292:
		device_type = "Smart Keyboard Folio 11\""
	elif product_id == 0x293:
		device_type = "Smart Keyboard Folio 12.9\""
	else:
		# not supported at the moment
		return 0
	
	
	return {'format': "Accessory Firmware Update (%s)" % device_type, 'processor':'ARM'}
	
	
def load_file(li, neflags, format):
	# ensure we are not wrongly called
	if not format.startswith("Accessory Firmware Update"):
		return 0

	li.seek(0)
	data = li.read(0x14)
	(magic, xxx1, fw_type, fw_ver, fw_len, unk1, product_id, hw_rev_id) = struct.unpack("<HHHHIIHH", data)

	li.seek(0x20)
	AFU_signature_header_data = li.read(24)

	(sig_magic, unknown1, unknown2, digest_type, digest_len, digest_offset, sig_type, sig_len, sig_offset) = struct.unpack("<IHHHHIHHI", AFU_signature_header_data)

	idaapi.set_processor_type("ARM:ARMv7-M", ida_idp.SETPROC_ALL)

	if product_id == 0x312: # Apple Pencil
		fw_base = 0x8006080
		msp_base = fw_base		
	elif product_id == 0x268: # Smart Keyboard 12.9"
		fw_base = 0x08002600
		msp_base = fw_base
	elif product_id == 0x26A: # Smart Keyboard 9.7"
		fw_base = 0x08002600
		msp_base = fw_base
	elif product_id == 0x26B: # Smart Keyboard 10.5"
		fw_base = 0x08002600        # don't really know, haven't seen an OTA so far
		msp_base = fw_base
	elif product_id == 0x292: # Smart Keyboard Folio 11"
		fw_base = 0x08000980        # seems to work
		msp_base = fw_base + 0x180
	elif product_id == 0x293: # Smart Keyboard Folio 12.9"
		fw_base = 0x08000980        # seems to work
		msp_base = fw_base + 0x180
	else:
		return 0


	li.file2base(0, fw_base-0x80, fw_base, 1)
	li.file2base(0x80, fw_base, fw_base+fw_len, 1)
		
	idaapi.add_segm(0, fw_base-0x80, fw_base, "HEADER", "DATA")
	idaapi.add_segm(0, fw_base, fw_base+fw_len, "__TEXT", "CODE")
	idaapi.add_segm(0, 0xE000E000, 0xE000F000, "__SYSREG", "DATA")
	idaapi.add_segm(0, SRAM_BASE, SRAM_BASE+SRAM_SIZE, "__SRAM", "DATA")

	idc.split_sreg_range(fw_base-0x80, "T", 1)
	idc.split_sreg_range(fw_base, "T", 1)
	
	# register the structures
	register_structs()
	
	# apply the structure
	idc.set_name(fw_base - 0x80, "AFU_HEADER")
	idc.create_struct(fw_base - 0x80, -1, "afu_full_header")
	ida_nalt.unhide_item(fw_base - 0x80 + 1)
	
	# handle the digest and signature
	
	if sig_magic == 0x61E34724:
		
		# apply the structure
		idc.set_name(fw_base - 0x80 + 0x20, "AFU_SIG_HEADER")
		#idc.create_struct(fw_base - 0x80 + 0x20, -1, "afu_sig_header")
		#ida_nalt.unhide_item(fw_base - 0x80 + 0x20 + 1)
		
		# first handle the digest
		base = fw_base+fw_len
		li.file2base(digest_offset, base, base+digest_len, 1)
		idaapi.add_segm(0, base, base+digest_len, "__DIGEST", "DATA")
		idc.create_byte(base)
		idc.make_array(base, digest_len)
		idc.set_name(base, "AFU_DIGEST")

		# now handle the signature
		base += digest_len
		li.file2base(sig_offset, base, base+sig_len, 1)
		idaapi.add_segm(0, base, base+sig_len, "__SIGNATURE", "DATA")
		idc.create_byte(base)
		idc.make_array(base, sig_len)
		idc.set_name(base, "AFU_SIGNATURE")

	# check if __TEXT starts with an SRAM address
	# this is the initial MSP that is followed by exception vectors
	initMSP = idc.Dword(msp_base)
	print "initMSP 0x%x" % initMSP
	if (initMSP >= SRAM_BASE) and initMSP <= (SRAM_BASE+SRAM_SIZE):
		
		idc.set_name(msp_base, "init_MSP")
		idc.create_dword(msp_base)
		idc.op_plain_offset(msp_base, -1, 0)
		idc.set_cmt(msp_base, "Initial MSP value", 0)
		
		# these are now the exception vectors
		
		# determine how many exception vectors there are
		cnt = 0
		handlers = {}
		last_multi = None
		multi = False
		
		while cnt < 255:
			ptr = idc.Dword(msp_base + 4 + 4 * cnt)
			if ptr != 0:
				
				# must be inside __TEXT
				if (ptr < fw_base) or (ptr > fw_base+fw_len):
					break
					
				if (ptr & 1) == 0: # must be thumb mode
					break
			
			# convert into a dword + offset
			idc.create_dword(msp_base + 4 + 4 * cnt)
			if ptr != 0:
				idc.op_offset(msp_base + 4 + 4 * cnt, 0, idc.REF_OFF32, -1, 0, 0)
			idc.set_cmt(msp_base + 4 + 4 * cnt, "exception %d: %s" % (cnt + 1, exception_table[cnt + 1]), 0)
			
			# should only RESET vector be our entrypoint?
			idc.add_entry(ptr & ~1, ptr & ~1, "", 1)
			
			# remember how often we see each handler
			if ptr != 0:
				if handlers.has_key(ptr):
					handlers[ptr] += 1
					if last_multi != None:
						if last_multi != ptr:
							multi = True
					last_multi = ptr
				else:
					handlers[ptr] = 1
			 
			cnt += 1
		
		print "cnt: %d" % cnt
		
		if cnt > 0:
			i = 1
			while i <= cnt:
				ptr = idc.Dword(msp_base + 4 * i)
				
				if ptr != 0:
					# ensure this is 
					if handlers[ptr] == 1:
						idc.set_name(ptr & ~1, "%s_%s" % (EXCEPTION_PREFIX, exception_table[i]))
						
					elif not multi:
						idc.set_name(ptr & ~1, "%s_%s" % (EXCEPTION_PREFIX, "UNIMPL"))
						
				i += 1
				
	
	

	

	return 1
