x64:
    load "loader.x64.o"
        make pic +gofirst

    load "../../shared/resolve.x64.o"
        merge

    mergelib "../../libtcg/libtcg.x64.zip"

    dfr "resolve" "ror13" "KERNEL32, NTDLL"
    dfr "resolve_ext" "strings"

    # carokann.bin → sección "carokann"
    # debe coincidir con: char _carokann_[0] __attribute__((section("carokann")));
    load "carokann.bin"
        preplen
        link "carokann"

    export