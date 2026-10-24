x64:
    load "payload.x64.o"
        make pic +gofirst

    load "../../shared/resolve.x64.o"
        merge

    mergelib "../../libtcg/libtcg.x64.zip"

    dfr "resolve" "ror13" "KERNEL32, NTDLL"
    dfr "resolve_ext" "strings"

    export