// PC Language Standard Library - Built-in Functions (Refactored)
const std = @import("std");
const Interpreter = @import("../interpreter.zig").Interpreter;
const Value = @import("../interpreter.zig").Value;
const InterpreterError = @import("../interpreter.zig").InterpreterError;
const process = @import("process.zig");
const network = @import("network.zig");
const autoexploit = @import("autoexploit.zig");
const crypto = @import("crypto.zig");
const string_utils = @import("string_utils.zig");
const web = @import("web.zig");
const forensics = @import("forensics.zig");
const reverse = @import("reverse.zig");

// Function signature for all built-in functions
pub const BuiltinFn = *const fn (*Interpreter, []Value) InterpreterError!Value;

// Built-in function map
pub const builtins = std.StaticStringMap(BuiltinFn).initComptime(.{
    .{ "print", builtin_print },
    .{ "len", builtin_len },
    .{ "range", builtin_range },
    .{ "str", builtin_str },
    .{ "int", builtin_int },
    .{ "p32", builtin_p32 },
    .{ "p64", builtin_p64 },
    .{ "unpack32", builtin_unpack32 },
    .{ "unpack64", builtin_unpack64 },
    .{ "hex", builtin_hex },
    .{ "abs", builtin_abs },
    .{ "max", builtin_max },
    .{ "min", builtin_min },
    .{ "pow", builtin_pow },
    .{ "upper", builtin_upper },
    .{ "lower", builtin_lower },
    .{ "append", builtin_append },
    .{ "keys", builtin_keys },
    .{ "values", builtin_values },
    // Process functions
    .{ "process", process.builtin_process },
    .{ "proc_send", process.builtin_proc_send },
    .{ "proc_sendline", process.builtin_proc_sendline },
    .{ "proc_recv", process.builtin_proc_recv },
    .{ "proc_recvline", process.builtin_proc_recvline },
    .{ "proc_recvuntil", process.builtin_proc_recvuntil },
    .{ "proc_sendafter", process.builtin_proc_sendafter },
    .{ "proc_interactive", process.builtin_proc_interactive },
    // Network functions
    .{ "remote", network.builtin_remote },
    .{ "listen", network.builtin_listen },
    .{ "sock_send", network.builtin_sock_send },
    .{ "sock_sendline", network.builtin_sock_sendline },
    .{ "sock_recv", network.builtin_sock_recv },
    .{ "sock_recvline", network.builtin_sock_recvline },
    .{ "sock_recvuntil", network.builtin_sock_recvuntil },
    .{ "sock_sendafter", network.builtin_sock_sendafter },
    // Auto Exploit functions
    .{ "AutoExploit", autoexploit.builtin_auto_exploit },
    .{ "ae_set_binary", autoexploit.builtin_ae_set_binary },
    .{ "ae_set_libc_base", autoexploit.builtin_ae_set_libc_base },
    .{ "ae_add_gadget", autoexploit.builtin_ae_add_gadget },
    .{ "ae_build_payload", autoexploit.builtin_ae_build_payload },
    .{ "ae_leak_address", autoexploit.builtin_ae_leak_address },
    .{ "ae_find_libc_base", autoexploit.builtin_ae_find_libc_base },
    // Crypto functions
    .{ "md5", crypto.builtin_md5 },
    .{ "sha1", crypto.builtin_sha1 },
    .{ "sha256", crypto.builtin_sha256 },
    .{ "sha512", crypto.builtin_sha512 },
    .{ "base64_encode", crypto.builtin_base64_encode },
    .{ "base64_decode", crypto.builtin_base64_decode },
    .{ "rsa_parse_pem", crypto.builtin_rsa_parse_pem },
    .{ "rsa_decrypt", crypto.builtin_rsa_decrypt },
    .{ "rsa_factor_small", crypto.builtin_rsa_factor_small },
    .{ "rsa_common_e", crypto.builtin_rsa_common_e },
    .{ "xor_bytes", crypto.builtin_xor_bytes },
    .{ "rot13", crypto.builtin_rot13 },
    .{ "hex_encode", crypto.builtin_hex_encode },
    .{ "hex_decode", crypto.builtin_hex_decode },
    .{ "rsa_attack_factordb", crypto.builtin_rsa_attack_factordb },
    .{ "rsa_attack_fermat", crypto.builtin_rsa_attack_fermat },
    .{ "rsa_attack_wiener", crypto.builtin_rsa_attack_wiener },
    .{ "rsa_compute_d", crypto.builtin_rsa_compute_d },
    .{ "rsa_decrypt_with_pqe", crypto.builtin_rsa_decrypt_with_pqe },
    .{ "aes_encrypt", crypto.builtin_aes_encrypt },
    .{ "aes_decrypt", crypto.builtin_aes_decrypt },
    .{ "read_file", crypto.builtin_read_file },
    .{ "write_file", crypto.builtin_write_file },
    .{ "shellcode_execve", crypto.builtin_shellcode_execve },
    .{ "bytes_to_long", crypto.builtin_bytes_to_long },
    .{ "long_to_bytes", crypto.builtin_long_to_bytes },
    // String utilities
    .{ "split", string_utils.builtin_split },
    .{ "join", string_utils.builtin_join },
    .{ "replace", string_utils.builtin_replace },
    .{ "strip", string_utils.builtin_strip },
    .{ "startswith", string_utils.builtin_startswith },
    .{ "endswith", string_utils.builtin_endswith },
    .{ "find", string_utils.builtin_find },
    .{ "chr", string_utils.builtin_chr },
    .{ "ord", string_utils.builtin_ord },
    .{ "bin", string_utils.builtin_bin },
    .{ "oct", string_utils.builtin_oct },
    .{ "unhex", string_utils.builtin_unhex },
    // Web exploitation
    .{ "http_get", web.builtin_http_get },
    .{ "http_post", web.builtin_http_post },
    .{ "sqli_union", web.builtin_sqli_union },
    .{ "sqli_time_based", web.builtin_sqli_time_based },
    .{ "sqli_error_based", web.builtin_sqli_error_based },
    .{ "xss_basic", web.builtin_xss_basic },
    .{ "xss_img_onerror", web.builtin_xss_img_onerror },
    .{ "xss_svg_onload", web.builtin_xss_svg_onload },
    .{ "lfi_linux", web.builtin_lfi_linux },
    .{ "lfi_php_wrapper", web.builtin_lfi_php_wrapper },
    .{ "url_encode", web.builtin_url_encode },
    .{ "url_decode", web.builtin_url_decode },
    // Forensics & Analysis
    .{ "detect_filetype", forensics.builtin_detect_filetype },
    .{ "get_magic_bytes", forensics.builtin_get_magic_bytes },
    .{ "strings_extract", forensics.builtin_strings_extract },
    .{ "hex_dump", forensics.builtin_hex_dump },
    .{ "extract_zip", forensics.builtin_extract_zip },
    .{ "extract_lsb", forensics.builtin_extract_lsb },
    .{ "parse_pcap", forensics.builtin_parse_pcap },
    // Reverse Engineering
    .{ "parse_elf", reverse.builtin_parse_elf },
    .{ "elf_symbols", reverse.builtin_elf_symbols },
    .{ "elf_strings", reverse.builtin_elf_strings },
    .{ "find_gadgets", reverse.builtin_find_gadgets },
    .{ "find_syscall", reverse.builtin_find_syscall },
    .{ "asm", reverse.builtin_asm },
    .{ "disasm", reverse.builtin_disasm },
    .{ "checksec", reverse.builtin_checksec },
    .{ "file_info", reverse.builtin_file_info },
    .{ "cyclic", reverse.builtin_cyclic },
    .{ "cyclic_find", reverse.builtin_cyclic_find },
    .{ "shellcode_nop", reverse.builtin_shellcode_nop },
    .{ "shellcode_int80", reverse.builtin_shellcode_int80 },
});

// ============================================================================
// Built-in Function Implementations
// ============================================================================

// print(*args) - Output to stdout
fn builtin_print(interp: *Interpreter, args: []Value) InterpreterError!Value {
    for (args) |arg| {
        try interp.stdout.print("{}", .{arg});
    }
    try interp.stdout.print("\n", .{});
    return Value.None;
}

// len(obj) - Return length of string or list
fn builtin_len(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0) return Value{ .Int = 0 };
    return switch (args[0]) {
        .String => |s| Value{ .Int = @intCast(s.len) },
        .List => |l| Value{ .Int = @intCast(l.items.len) },
        .Dict => |d| Value{ .Int = @intCast(d.count()) },
        else => Value{ .Int = 0 },
    };
}

// range(n) - Return max value for iteration
fn builtin_range(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0) return Value{ .Int = 0 };
    return switch (args[0]) {
        .Int => args[0],
        else => Value{ .Int = 0 },
    };
}

// str(x) - Convert to string
fn builtin_str(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0) return Value{ .String = "" };
    
    const str_val = switch (args[0]) {
        .Int => |i| try std.fmt.allocPrint(interp.allocator, "{}", .{i}),
        .Float => |f| try std.fmt.allocPrint(interp.allocator, "{d}", .{f}),
        .Bool => |b| if (b) "true" else "false",
        .String => |s| s,
        .None => "None",
        else => "<object>",
    };
    return Value{ .String = str_val };
}

// int(x) - Convert to integer
fn builtin_int(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0) return Value{ .Int = 0 };
    
    const int_val = switch (args[0]) {
        .Int => |i| i,
        .Float => |f| @as(i64, @intFromFloat(f)),
        .Bool => |b| if (b) @as(i64, 1) else @as(i64, 0),
        .String => |s| std.fmt.parseInt(i64, s, 10) catch 0,
        else => 0,
    };
    return Value{ .Int = int_val };
}

// p32(value) - Pack 32-bit integer to bytes (little-endian)
fn builtin_p32(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .Int) return Value{ .String = "" };
    
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, @intCast(args[0].Int), .little);
    const str = try interp.allocator.dupe(u8, &result);
    return Value{ .String = str };
}

// p64(value) - Pack 64-bit integer to bytes (little-endian)
fn builtin_p64(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .Int) return Value{ .String = "" };
    
    var result: [8]u8 = undefined;
    std.mem.writeInt(u64, &result, @intCast(args[0].Int), .little);
    const str = try interp.allocator.dupe(u8, &result);
    return Value{ .String = str };
}

// unpack32(bytes) - Unpack 32-bit integer from bytes
fn builtin_unpack32(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .Int = 0 };
    if (args[0].String.len < 4) return Value{ .Int = 0 };
    
    const bytes = args[0].String[0..4];
    const result = std.mem.readInt(u32, bytes[0..4], .little);
    return Value{ .Int = @intCast(result) };
}

// unpack64(bytes) - Unpack 64-bit integer from bytes
fn builtin_unpack64(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .Int = 0 };
    if (args[0].String.len < 8) return Value{ .Int = 0 };
    
    const bytes = args[0].String[0..8];
    const result = std.mem.readInt(u64, bytes[0..8], .little);
    return Value{ .Int = @bitCast(result) };
}

// hex(value) - Convert to hex string
fn builtin_hex(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .Int) return Value{ .String = "" };
    
    const hex_str = try std.fmt.allocPrint(interp.allocator, "0x{x}", .{args[0].Int});
    return Value{ .String = hex_str };
}

// abs(x) - Absolute value
fn builtin_abs(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0) return Value{ .Int = 0 };
    
    return switch (args[0]) {
        .Int => |i| Value{ .Int = if (i < 0) -i else i },
        .Float => |f| Value{ .Float = @abs(f) },
        else => Value{ .Int = 0 },
    };
}

// max(a, b) - Maximum of two values
fn builtin_max(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value{ .Int = 0 };
    if (args[0] != .Int or args[1] != .Int) return Value{ .Int = 0 };
    
    return Value{ .Int = @max(args[0].Int, args[1].Int) };
}

// min(a, b) - Minimum of two values
fn builtin_min(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value{ .Int = 0 };
    if (args[0] != .Int or args[1] != .Int) return Value{ .Int = 0 };
    
    return Value{ .Int = @min(args[0].Int, args[1].Int) };
}

// pow(base, exp) - Power function
fn builtin_pow(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value{ .Int = 0 };
    if (args[0] != .Int or args[1] != .Int) return Value{ .Int = 0 };
    
    const result = std.math.pow(f64, @floatFromInt(args[0].Int), @floatFromInt(args[1].Int));
    return Value{ .Float = result };
}

// upper(s) - Convert string to uppercase
fn builtin_upper(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .String = "" };
    
    const result = try interp.allocator.alloc(u8, args[0].String.len);
    for (args[0].String, 0..) |c, i| {
        result[i] = std.ascii.toUpper(c);
    }
    return Value{ .String = result };
}

// lower(s) - Convert string to lowercase
fn builtin_lower(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .String = "" };
    
    const result = try interp.allocator.alloc(u8, args[0].String.len);
    for (args[0].String, 0..) |c, i| {
        result[i] = std.ascii.toLower(c);
    }
    return Value{ .String = result };
}

// append(list, value) - Return new list with value appended
fn builtin_append(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len != 2) return Value.None;
    if (args[0] != .List) return Value.None;
    
    // Create new list with appended value
    var new_list = std.ArrayList(Value).init(interp.allocator);
    try new_list.appendSlice(args[0].List.items);
    try new_list.append(args[1]);
    return Value{ .List = new_list };
}

// keys(dict) - Return list of dictionary keys
fn builtin_keys(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .Dict) return Value.None;
    
    var key_list = std.ArrayList(Value).init(interp.allocator);
    var it = args[0].Dict.keyIterator();
    while (it.next()) |key| {
        try key_list.append(Value{ .String = key.* });
    }
    return Value{ .List = key_list };
}

// values(dict) - Return list of dictionary values
fn builtin_values(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .Dict) return Value.None;
    
    var val_list = std.ArrayList(Value).init(interp.allocator);
    var it = args[0].Dict.valueIterator();
    while (it.next()) |val| {
        try val_list.append(val.*);
    }
    return Value{ .List = val_list };
}
