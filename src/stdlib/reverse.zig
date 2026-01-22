// PC Language - Reverse Engineering Module
const std = @import("std");
const Interpreter = @import("../interpreter.zig").Interpreter;
const Value = @import("../interpreter.zig").Value;
const InterpreterError = @import("../interpreter.zig").InterpreterError;

// ============================================================================
// ELF File Parsing
// ============================================================================

// parse_elf(path) - Parse ELF file and return dict with info
pub fn builtin_parse_elf(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value.None;
    }
    
    const path = args[0].String;
    const file = std.fs.cwd().openFile(path, .{}) catch return Value.None;
    defer file.close();
    
    // Read ELF header (64 bytes for 64-bit)
    var header: [64]u8 = undefined;
    const bytes_read = file.read(&header) catch return Value.None;
    if (bytes_read < 64) return Value.None;
    
    // Check ELF magic
    if (!std.mem.eql(u8, header[0..4], &[_]u8{0x7F, 0x45, 0x4C, 0x46})) {
        return Value.None; // Not an ELF file
    }
    
    // Parse basic info
    var result = std.StringHashMap(Value).init(interp.allocator);
    
    // Class (32 or 64 bit)
    const class = header[4];
    const class_str = if (class == 1) "ELF32" else if (class == 2) "ELF64" else "Unknown";
    try result.put("class", Value{ .String = try interp.allocator.dupe(u8, class_str) });
    
    // Endianness
    const endian = header[5];
    const endian_str = if (endian == 1) "Little Endian" else if (endian == 2) "Big Endian" else "Unknown";
    try result.put("endian", Value{ .String = try interp.allocator.dupe(u8, endian_str) });
    
    // Type
    const elf_type = std.mem.readInt(u16, header[16..18], .little);
    const type_str = switch (elf_type) {
        1 => "REL (Relocatable)",
        2 => "EXEC (Executable)",
        3 => "DYN (Shared object)",
        4 => "CORE (Core file)",
        else => "Unknown",
    };
    try result.put("type", Value{ .String = try interp.allocator.dupe(u8, type_str) });
    
    // Machine architecture
    const machine = std.mem.readInt(u16, header[18..20], .little);
    const arch_str = switch (machine) {
        0x3E => "x86-64",
        0x03 => "x86",
        0xB7 => "AArch64",
        0x28 => "ARM",
        else => "Unknown",
    };
    try result.put("arch", Value{ .String = try interp.allocator.dupe(u8, arch_str) });
    
    // Entry point (for 64-bit)
    if (class == 2) {
        const entry = std.mem.readInt(u64, header[24..32], .little);
        try result.put("entry_point", Value{ .Int = @intCast(entry) });
    }
    
    return Value{ .Dict = result };
}

// elf_symbols(path) - Extract symbol names from ELF
pub fn builtin_elf_symbols(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    }
    
    const path = args[0].String;
    
    // Use readelf to get symbols
    const script = try std.fmt.allocPrint(interp.allocator,
        \\readelf -s '{s}' 2>/dev/null | grep -E '^\s*[0-9]+:' | awk '{{print $8}}' | grep -v '^$' | head -50
    , .{path});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    defer interp.allocator.free(result);
    
    // Parse output into list
    var symbols = std.ArrayList(Value).init(interp.allocator);
    var it = std.mem.splitScalar(u8, result, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 0) {
            const symbol = try interp.allocator.dupe(u8, trimmed);
            try symbols.append(Value{ .String = symbol });
        }
    }
    
    return Value{ .List = symbols };
}

// elf_strings(path, min_length) - Extract strings from binary
pub fn builtin_elf_strings(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    }
    
    const path = args[0].String;
    var min_len: i64 = 4;
    if (args.len >= 2 and args[1] == .Int) {
        min_len = args[1].Int;
    }
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\strings -n {d} '{s}' | head -100
    , .{min_len, path});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    defer interp.allocator.free(result);
    
    var strings = std.ArrayList(Value).init(interp.allocator);
    var it = std.mem.splitScalar(u8, result, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 0) {
            const str = try interp.allocator.dupe(u8, trimmed);
            try strings.append(Value{ .String = str });
        }
    }
    
    return Value{ .List = strings };
}

// ============================================================================
// ROP Gadget Searching
// ============================================================================

// find_gadgets(binary, pattern) - Find ROP gadgets
pub fn builtin_find_gadgets(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .String) {
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    }
    
    const binary = args[0].String;
    const pattern = args[1].String;
    
    // Use ROPgadget if available
    const script = try std.fmt.allocPrint(interp.allocator,
        \\ROPgadget --binary '{s}' --only '{s}' 2>/dev/null | grep '^0x' | head -20
    , .{binary, pattern});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    defer interp.allocator.free(result);
    
    var gadgets = std.ArrayList(Value).init(interp.allocator);
    var it = std.mem.splitScalar(u8, result, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 0) {
            const gadget = try interp.allocator.dupe(u8, trimmed);
            try gadgets.append(Value{ .String = gadget });
        }
    }
    
    return Value{ .List = gadgets };
}

// find_syscall(binary) - Find syscall gadget
pub fn builtin_find_syscall(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .String = "" };
    }
    
    const binary = args[0].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\ROPgadget --binary '{s}' --only 'syscall' 2>/dev/null | grep '^0x' | head -1
    , .{binary});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .String = "" };
    
    return Value{ .String = result };
}

// ============================================================================
// Assembly & Disassembly
// ============================================================================

// asm(code, arch) - Assemble instruction to bytes
pub fn builtin_asm(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .String = "" };
    }
    
    const code = args[0].String;
    var arch: []const u8 = "x64";
    if (args.len >= 2 and args[1] == .String) {
        arch = args[1].String;
    }
    
    // Use pwntools to assemble
    const script = try std.fmt.allocPrint(interp.allocator,
        \\from pwn import *
        \\context.arch = '{s}'
        \\code = asm('{s}')
        \\print(code.hex())
    , .{arch, code});
    defer interp.allocator.free(script);
    
    const result = executePythonScript(interp.allocator, script) catch 
        return Value{ .String = "" };
    
    return Value{ .String = result };
}

// disasm(bytes, arch) - Disassemble bytes to instructions
pub fn builtin_disasm(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .String = "" };
    }
    
    const bytes_hex = args[0].String;
    var arch: []const u8 = "x64";
    if (args.len >= 2 and args[1] == .String) {
        arch = args[1].String;
    }
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\from pwn import *
        \\context.arch = '{s}'
        \\code = bytes.fromhex('{s}')
        \\print(disasm(code))
    , .{arch, bytes_hex});
    defer interp.allocator.free(script);
    
    const result = executePythonScript(interp.allocator, script) catch 
        return Value{ .String = "" };
    
    return Value{ .String = result };
}

// ============================================================================
// Dynamic Analysis Helpers
// ============================================================================

// checksec(binary) - Check binary security features
pub fn builtin_checksec(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value.None;
    }
    
    const binary = args[0].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\checksec --file='{s}' 2>/dev/null || echo "checksec not found"
    , .{binary});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .String = "Error" };
    
    return Value{ .String = result };
}

// file_info(path) - Get file information
pub fn builtin_file_info(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .String = "" };
    }
    
    const path = args[0].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\file '{s}' 2>/dev/null
    , .{path});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .String = "" };
    
    return Value{ .String = result };
}

// ============================================================================
// Pattern Generation (for buffer overflow)
// ============================================================================

// cyclic(length) - Generate cyclic pattern
pub fn builtin_cyclic(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .Int) {
        return Value{ .String = "" };
    }
    
    const length = args[0].Int;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\from pwn import *
        \\print(cyclic({d}).decode('latin1'))
    , .{length});
    defer interp.allocator.free(script);
    
    const result = executePythonScript(interp.allocator, script) catch 
        return Value{ .String = "" };
    
    return Value{ .String = result };
}

// cyclic_find(substring) - Find offset in cyclic pattern
pub fn builtin_cyclic_find(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .Int = -1 };
    }
    
    const substring = args[0].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\from pwn import *
        \\print(cyclic_find('{s}'))
    , .{substring});
    defer interp.allocator.free(script);
    
    const result = executePythonScript(interp.allocator, script) catch 
        return Value{ .Int = -1 };
    
    const offset = std.fmt.parseInt(i64, std.mem.trim(u8, result, " \t\r\n"), 10) catch -1;
    return Value{ .Int = offset };
}

// ============================================================================
// Shellcode Utilities
// ============================================================================

// shellcode_nop_sled(length) - Generate NOP sled
pub fn builtin_shellcode_nop(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .Int) {
        return Value{ .String = "" };
    }
    
    const length = args[0].Int;
    const nops = try interp.allocator.alloc(u8, @intCast(length));
    @memset(nops, 0x90); // NOP instruction
    
    return Value{ .String = nops };
}

// shellcode_int80() - Generate int 0x80 shellcode (x86)
pub fn builtin_shellcode_int80(interp: *Interpreter, _: []Value) InterpreterError!Value {
    const shellcode = try interp.allocator.dupe(u8, "\xcd\x80"); // int 0x80
    return Value{ .String = shellcode };
}

// ============================================================================
// Helper Functions
// ============================================================================

fn executeShellCommand(allocator: std.mem.Allocator, command: []const u8) ![]u8 {
    var child = std.process.Child.init(&[_][]const u8{"sh", "-c", command}, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    
    try child.spawn();
    
    const stdout = try child.stdout.?.readToEndAlloc(allocator, 10 * 1024 * 1024);
    _ = try child.wait();
    
    return stdout;
}

fn executePythonScript(allocator: std.mem.Allocator, script: []const u8) ![]u8 {
    const temp_path = "/tmp/pc_reverse_script.py";
    {
        const file = try std.fs.cwd().createFile(temp_path, .{});
        defer file.close();
        try file.writeAll(script);
    }
    
    var child = std.process.Child.init(&[_][]const u8{"python3", temp_path}, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    
    try child.spawn();
    
    const stdout = try child.stdout.?.readToEndAlloc(allocator, 10 * 1024 * 1024);
    _ = try child.wait();
    
    return stdout;
}
