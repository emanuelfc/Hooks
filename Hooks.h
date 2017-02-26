namespace DetourHook
{
	class DetourHook
	{
		private:
		
			// Variables
			void* hkSrc;				// Memory address where to place hook code
			byte* hkCode;				// Hook code - memory already allocated
			byte* originalCode;			// Original code to be replaced - memory already allocated
			
			/*
				Hook code and size must take in account original code size in order to not
				corrupt instructions
			*/
			
			// Functions
			
			bool modifyCode(const void* src, const void* bytes, const size_t size);
			
		public:
		
			// Constructors
			/*
				Sets up a detour hook.
				Does not hook right away, check hook function after
				constructing object.
			*/
			DetourHook(void* hkSrc, byte* hkCode, byte* originalCode, size_t size);
			
			// Destructor
			~DetourHook();
			
			// Functions
			
			/*
				Hooks the hook code to the desired memory location
				
				Return:
						True - hook placed
						False - hook failed, attempted to restore original code, but region may be corrupted
			*/
			bool hook();
			
			/*
				Unhooks the hook, replacing it with its original code.
				
				Return:
						True - unhook successful, original code in place
						False - unhook failed, hook location may be corrupted
			*/
			bool unhook();
			
	};
}