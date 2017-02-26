/*

	Makes code non-architecture dependent.
	
	Only supports 32 or 64 bit architectures.

*/

#if // 64 bit arch
	#define 
#elseif // 32 bit arch
	#define 
#else
	#error Unsupported architecture. 32/64 bits only.
#endif

DetourHook::DetourHook(void* hkSrc, byte* hkCode, byte* originalCode, size_t size)
{
	this->hkSrc = hkSrc;
	this->hkCode = hkCode;
	this->originalCode = originalCode;
	this->size = size;
}

DetourHook::~DetourHook()
{
	unhook();
}

// Checks hook length
void length()
{
}

// Install hook
bool DetourHook::hook()
{
	/* Compare src code with original code, if equal, modify */
	if(memcmp(hkSrc, originalCode, size) == 0)
	{
		uint32_t oldProt;
		if(VirtualProtect(hkSrc, size, PAGE_EXECUTE_READWRITE, &oldProt))
		{
			// Successfully changed process page protection to modify code
			
			// Write hook to memory
			unsigned int bytesCopied = (unsigned char*)memcpy(hkSrc, hkCode, size) - (unsigned char*)hkSrc;
			
			if(bytesCopied != 0 && bytesCopied < size)
			{
				memcpy(hkSrc, originalCode, bytesCopied); // Restore original code in case of hook code copy error
				hooked = false;
			}
			else hooked = true;

			VirtualProtect(hkSrc, size, oldProt, NULL);
			FlushInstructionCache(GetCurrentProcess(), hkSrc, size);
			
			return hooked;
		}
	}
	
	return false;
}

/* sanity constructor
DetourHook initHook(void* hkSrc, byte* hkCode, byte* originalCode, size_t size)
{
	if(hkSrc == NULL || hkCode == NULL || originalCode == NULL || size <= 0) return NULL;
	else return DetourHook(hkSrc, hkCode, originalCode, size);
}
*/

// Remove hook
bool DetourHook::unhook()
{
	/* Compare hooked code with hook source code, if equal, modify */
	if(memcmp(hkSrc, hkCode, size) == 0)
	{
		uint32_t oldProt;
		if(VirtualProtect(hkSrc, size, PAGE_EXECUTE_READWRITE, &oldProt))
		{
			// Successfully changed process page protection to modify code
			
			bool hooked = true;
			
			// Write hook to memory
			if((unsigned char*)memcpy(hkSrc, originalCode, size) != hkSrc + size) hooked = false;

			VirtualProtect(hkSrc, hkSize, oldProt, NULL);
			FlushInstructionCache(GetCurrentProcess(), hkSrc, hkSize);
			
			return hooked;
		}
	}
	
	return false;
}

/*
	Modify page code

	Unchecked Conditions: 	VirtualProtect
							memcpy
							FlushInstructionCache
*/

/* old code
bool DetourHook::modifyCode(const void* src, const void* bytes, const size_t size)
{
	uint32_t oldProt;
	
	if(VirtualProtect(src, size, PAGE_EXECUTE_READWRITE, &oldProt))
	{
		// Successfully changed process page protection to modify code
		
		// Write hook to memory
		unsigned int bytesCopied = (unsigned char*)memcpy(src, bytes, size) - (unsigned char*)src;
		
		if(bytesCopied != 0 && bytesCopied < size) memcpy(src, originalCode, bytesCopied); // Restore original code in case of hook code copy error

		VirtualProtect(src, size, oldProt, NULL);
		FlushInstructionCache(GetCurrentProcess(), hkSrc, hkSize);
	}
	//else Error: Failed VirtualProtect
	
	
#ifdef DEBUG
		error();
#endif
	
	return false;
}
*/

#ifdef DEBUG

void error()
{
	DWORD error = GetLastError();
	printf("[Error] %d", error);
}

#endif
/*

	Errors:

- Failed FlushInstructionCache
Unable to flush instruction cache.
Current process may still execute the
same old code that is in it's instruction cache, 
there is no certanty that the process 
will or will not execute the newly changed code.

- Failed VirtualProtect
Unable to change process page protection.
Cannot change the page protection value
to desired value in order to change the code.

- Failed memcpy
Unable to copy code to desired memory region.

	/*
		Source Code mismatch with supplied original code
		
		Maybe original code is wrong, outdated or
		code has already been modified. Another hook
		or something.
	*/

*/