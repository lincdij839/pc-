// PC Language Standard Library - Cryptography Module
const std = @import("std");
const Interpreter = @import("../interpreter.zig").Interpreter;
const Value = @import("../interpreter.zig").Value;
const InterpreterError = @import("../interpreter.zig").InterpreterError;

// ============================================================================
// Hash Functions
// ============================================================================

// md5(data) - Compute MD5 hash
pub fn builtin_md5(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .String = "" };
    
    var hash: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(args[0].String, &hash, .{});
    
    const hex_str = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(&hash)});
    return Value{ .String = hex_str };
}

// sha1(data) - Compute SHA1 hash
pub fn builtin_sha1(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .String = "" };
    
    var hash: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(args[0].String, &hash, .{});
    
    const hex_str = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(&hash)});
    return Value{ .String = hex_str };
}

// sha256(data) - Compute SHA256 hash
pub fn builtin_sha256(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .String = "" };
    
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(args[0].String, &hash, .{});
    
    const hex_str = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(&hash)});
    return Value{ .String = hex_str };
}

// sha512(data) - Compute SHA512 hash
pub fn builtin_sha512(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .String = "" };
    
    var hash: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(args[0].String, &hash, .{});
    
    const hex_str = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(&hash)});
    return Value{ .String = hex_str };
}

// ============================================================================
// Base64 Encoding/Decoding
// ============================================================================

// base64_encode(data) - Encode to base64
pub fn builtin_base64_encode(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .String = "" };
    
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(args[0].String.len);
    const encoded = try interp.allocator.alloc(u8, encoded_len);
    _ = encoder.encode(encoded, args[0].String);
    
    return Value{ .String = encoded };
}

// base64_decode(data) - Decode from base64
pub fn builtin_base64_decode(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .String = "" };
    
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(args[0].String) catch {
        return Value{ .String = "" };
    };
    const decoded = try interp.allocator.alloc(u8, decoded_len);
    
    _ = decoder.decode(decoded, args[0].String) catch {
        return Value{ .String = "" };
    };
    
    return Value{ .String = decoded };
}

// ============================================================================
// RSA Functions
// ============================================================================

// Helper: Parse hex string to integer
fn parseHexString(allocator: std.mem.Allocator, hex_str: []const u8) ![]const u8 {
    var result = std.ArrayList(u8).init(allocator);
    var i: usize = 0;
    while (i + 1 < hex_str.len) : (i += 2) {
        const byte = try std.fmt.parseInt(u8, hex_str[i..i+2], 16);
        try result.append(byte);
    }
    return result.toOwnedSlice();
}

// rsa_parse_pem(pem_string) - Parse PEM format RSA public key
// Returns dict with "n" (modulus) and "e" (exponent) as hex strings
pub fn builtin_rsa_parse_pem(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value.None;
    
    const pem = args[0].String;
    
    // Remove PEM headers and decode base64
    var lines = std.mem.split(u8, pem, "\n");
    var base64_data = std.ArrayList(u8).init(interp.allocator);
    defer base64_data.deinit();
    
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "-----")) continue;
        if (line.len == 0) continue;
        try base64_data.appendSlice(line);
    }
    
    // Decode base64
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(base64_data.items) catch {
        return Value.None;
    };
    const decoded = try interp.allocator.alloc(u8, decoded_len);
    defer interp.allocator.free(decoded);
    
    decoder.decode(decoded, base64_data.items) catch {
        return Value.None;
    };
    const der_data = decoded[0..decoded_len];
    
    // Parse DER format (simplified parser)
    // For RSA public key, we look for the two large integers (n and e)
    var result = std.StringHashMap(Value).init(interp.allocator);
    
    // Find the modulus (n) and exponent (e) in DER
    // This is a simplified implementation
    var pos: usize = 0;
    var found_n = false;
    var found_e = false;
    
    while (pos < der_data.len - 4) : (pos += 1) {
        // Look for INTEGER tag (0x02)
        if (der_data[pos] == 0x02) {
            const len_byte = der_data[pos + 1];
            var int_len: usize = 0;
            var data_start: usize = 0;
            
            if (len_byte < 0x80) {
                // Short form
                int_len = len_byte;
                data_start = pos + 2;
            } else if (len_byte == 0x81) {
                // Long form (1 byte length)
                int_len = der_data[pos + 2];
                data_start = pos + 3;
            } else if (len_byte == 0x82) {
                // Long form (2 bytes length)
                int_len = (@as(usize, der_data[pos + 2]) << 8) | der_data[pos + 3];
                data_start = pos + 4;
            }
            
            if (data_start + int_len <= der_data.len) {
                const int_data = der_data[data_start..data_start + int_len];
                
                // Skip leading zero bytes
                var start: usize = 0;
                while (start < int_data.len and int_data[start] == 0) : (start += 1) {}
                const trimmed = int_data[start..];
                
                if (trimmed.len > 4 and !found_n) {
                    // This is likely the modulus (n)
                    const hex_str = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(trimmed)});
                    try result.put("n", Value{ .String = hex_str });
                    found_n = true;
                } else if (trimmed.len <= 4 and found_n and !found_e) {
                    // This is likely the exponent (e)
                    const hex_str = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(trimmed)});
                    try result.put("e", Value{ .String = hex_str });
                    found_e = true;
                    break;
                }
                
                pos = data_start + int_len - 1;
            }
        }
    }
    
    return Value{ .Dict = result };
}

// rsa_decrypt_basic(c, d, n) - Basic RSA decryption: m = c^d mod n
// All parameters as hex strings or integers
pub fn builtin_rsa_decrypt(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 3) return Value.None;
    
    // For CTF purposes, we'll return a placeholder
    // Real implementation would need big integer arithmetic
    const result = try std.fmt.allocPrint(interp.allocator, "RSA decryption not yet implemented - need big int library", .{});
    return Value{ .String = result };
}

// rsa_factor_small(n) - Try to factor small RSA modulus using trial division
pub fn builtin_rsa_factor_small(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0) return Value.None;
    
    var n: u64 = 0;
    switch (args[0]) {
        .Int => |i| n = @intCast(i),
        .String => |s| n = std.fmt.parseInt(u64, s, 10) catch return Value.None,
        else => return Value.None,
    }
    
    // Trial division up to sqrt(n)
    const limit = @as(u64, @intFromFloat(@sqrt(@as(f64, @floatFromInt(n))))) + 1;
    var i: u64 = 2;
    
    while (i <= limit) : (i += 1) {
        if (n % i == 0) {
            const p = i;
            const q = n / i;
            
            var result = std.StringHashMap(Value).init(interp.allocator);
            try result.put("p", Value{ .Int = @intCast(p) });
            try result.put("q", Value{ .Int = @intCast(q) });
            try result.put("factored", Value{ .Bool = true });
            
            return Value{ .Dict = result };
        }
    }
    
    var result = std.StringHashMap(Value).init(interp.allocator);
    try result.put("factored", Value{ .Bool = false });
    return Value{ .Dict = result };
}

// rsa_common_e() - Return common RSA exponents
pub fn builtin_rsa_common_e(interp: *Interpreter, _: []Value) InterpreterError!Value {
    var list = std.ArrayList(Value).init(interp.allocator);
    try list.append(Value{ .Int = 3 });
    try list.append(Value{ .Int = 5 });
    try list.append(Value{ .Int = 17 });
    try list.append(Value{ .Int = 257 });
    try list.append(Value{ .Int = 65537 });
    return Value{ .List = list };
}

// xor_bytes(data, key) - XOR encryption/decryption
pub fn builtin_xor_bytes(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .String) return Value{ .String = "" };
    
    const data = args[0].String;
    const key = args[1].String;
    
    if (key.len == 0) return Value{ .String = "" };
    
    const result = try interp.allocator.alloc(u8, data.len);
    for (data, 0..) |byte, i| {
        result[i] = byte ^ key[i % key.len];
    }
    
    return Value{ .String = result };
}

// rot13(text) - ROT13 cipher
pub fn builtin_rot13(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .String = "" };
    
    const text = args[0].String;
    const result = try interp.allocator.alloc(u8, text.len);
    
    for (text, 0..) |c, i| {
        if (c >= 'a' and c <= 'z') {
            result[i] = 'a' + @as(u8, @intCast((c - 'a' + 13) % 26));
        } else if (c >= 'A' and c <= 'Z') {
            result[i] = 'A' + @as(u8, @intCast((c - 'A' + 13) % 26));
        } else {
            result[i] = c;
        }
    }
    
    return Value{ .String = result };
}

// hex_encode(data) - Encode bytes to hex string
pub fn builtin_hex_encode(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .String = "" };
    
    const hex_str = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(args[0].String)});
    return Value{ .String = hex_str };
}

// hex_decode(hex_string) - Decode hex string to bytes
pub fn builtin_hex_decode(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .String = "" };
    
    const hex_str = args[0].String;
    if (hex_str.len % 2 != 0) return Value{ .String = "" };
    
    const result = try interp.allocator.alloc(u8, hex_str.len / 2);
    var i: usize = 0;
    
    while (i < hex_str.len) : (i += 2) {
        result[i / 2] = std.fmt.parseInt(u8, hex_str[i..i+2], 16) catch 0;
    }
    
    return Value{ .String = result };
}

// ============================================================================
// RSA Attack Functions (using external tools)
// ============================================================================

// rsa_attack_factordb(n_hex) - Query FactorDB for factorization
pub fn builtin_rsa_attack_factordb(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value.None;
    
    const n_hex = args[0].String;
    
    // Create Python script to query FactorDB
    const script = try std.fmt.allocPrint(interp.allocator,
        \\import requests
        \\import sys
        \\n = int('{s}', 16)
        \\url = f'http://factordb.com/api?query={{n}}'
        \\resp = requests.get(url).json()
        \\if resp['status'] == 'FF':
        \\    factors = [int(f[0]) for f in resp['factors']]
        \\    if len(factors) == 2:
        \\        print(f'{{factors[0]}},{{factors[1]}}')
        \\        sys.exit(0)
        \\sys.exit(1)
    , .{n_hex});
    defer interp.allocator.free(script);
    
    // Write script to temp file
    const tmp_path = "/tmp/pc_factordb.py";
    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return Value.None;
    defer file.close();
    file.writeAll(script) catch return Value.None;
    
    // Execute Python script
    var child = std.process.Child.init(&[_][]const u8{ "python3", tmp_path }, interp.allocator);
    child.stdout_behavior = .Pipe;
    child.spawn() catch return Value.None;
    
    const stdout = child.stdout.?.reader().readAllAlloc(interp.allocator, 4096) catch return Value.None;
    _ = child.wait() catch return Value.None;
    
    // Parse result
    if (std.mem.indexOf(u8, stdout, ",")) |comma_idx| {
        const p_str = stdout[0..comma_idx];
        const q_str = stdout[comma_idx + 1 ..];
        
        var result = std.StringHashMap(Value).init(interp.allocator);
        try result.put("p", Value{ .String = p_str });
        try result.put("q", Value{ .String = std.mem.trim(u8, q_str, " \n") });
        try result.put("factored", Value{ .Bool = true });
        return Value{ .Dict = result };
    }
    
    var result = std.StringHashMap(Value).init(interp.allocator);
    try result.put("factored", Value{ .Bool = false });
    return Value{ .Dict = result };
}

// rsa_attack_fermat(n_hex) - Fermat factorization attack
pub fn builtin_rsa_attack_fermat(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value.None;
    
    const n_hex = args[0].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\import sys
        \\n = int('{s}', 16)
        \\a = int(n ** 0.5) + 1
        \\for i in range(100000):
        \\    b2 = a*a - n
        \\    b = int(b2 ** 0.5)
        \\    if b*b == b2:
        \\        p = a - b
        \\        q = a + b
        \\        if p * q == n:
        \\            print(f'{{p}},{{q}}')
        \\            sys.exit(0)
        \\    a += 1
        \\sys.exit(1)
    , .{n_hex});
    defer interp.allocator.free(script);
    
    const tmp_path = "/tmp/pc_fermat.py";
    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return Value.None;
    defer file.close();
    file.writeAll(script) catch return Value.None;
    
    var child = std.process.Child.init(&[_][]const u8{ "python3", tmp_path }, interp.allocator);
    child.stdout_behavior = .Pipe;
    child.spawn() catch return Value.None;
    
    const stdout = child.stdout.?.reader().readAllAlloc(interp.allocator, 4096) catch return Value.None;
    const result_code = child.wait() catch return Value.None;
    
    if (result_code.Exited == 0) {
        if (std.mem.indexOf(u8, stdout, ",")) |comma_idx| {
            const p_str = stdout[0..comma_idx];
            const q_str = stdout[comma_idx + 1 ..];
            
            var result = std.StringHashMap(Value).init(interp.allocator);
            try result.put("p", Value{ .String = p_str });
            try result.put("q", Value{ .String = std.mem.trim(u8, q_str, " \n") });
            try result.put("factored", Value{ .Bool = true });
            return Value{ .Dict = result };
        }
    }
    
    var result = std.StringHashMap(Value).init(interp.allocator);
    try result.put("factored", Value{ .Bool = false });
    return Value{ .Dict = result };
}

// rsa_attack_wiener(n_hex, e_hex) - Wiener's attack for small d
pub fn builtin_rsa_attack_wiener(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .String) return Value.None;
    
    const n_hex = args[0].String;
    const e_hex = args[1].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\from fractions import Fraction
        \\import sys
        \\n = int('{s}', 16)
        \\e = int('{s}', 16)
        \\def continued_fractions(n, e):
        \\    cf = []
        \\    while e:
        \\        cf.append(n // e)
        \\        n, e = e, n % e
        \\    return cf
        \\def convergents(cf):
        \\    convs = []
        \\    for i in range(len(cf)):
        \\        num, den = Fraction(cf[i]), Fraction(1)
        \\        for j in range(i-1, -1, -1):
        \\            num, den = den, num
        \\            num += cf[j] * den
        \\        convs.append((num, den))
        \\    return convs
        \\cf = continued_fractions(e, n)
        \\convs = convergents(cf)
        \\for k, d in convs:
        \\    if k == 0: continue
        \\    phi = (e * d - 1) // k
        \\    b = n - phi + 1
        \\    det = b*b - 4*n
        \\    if det >= 0:
        \\        sqrt_det = int(det ** 0.5)
        \\        if sqrt_det * sqrt_det == det:
        \\            p = (b + sqrt_det) // 2
        \\            q = (b - sqrt_det) // 2
        \\            if p * q == n:
        \\                print(f'{{p}},{{q}},{{d}}')
        \\                sys.exit(0)
        \\sys.exit(1)
    , .{ n_hex, e_hex });
    defer interp.allocator.free(script);
    
    const tmp_path = "/tmp/pc_wiener.py";
    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return Value.None;
    defer file.close();
    file.writeAll(script) catch return Value.None;
    
    var child = std.process.Child.init(&[_][]const u8{ "python3", tmp_path }, interp.allocator);
    child.stdout_behavior = .Pipe;
    child.spawn() catch return Value.None;
    
    const stdout = child.stdout.?.reader().readAllAlloc(interp.allocator, 4096) catch return Value.None;
    const result_code = child.wait() catch return Value.None;
    
    if (result_code.Exited == 0) {
        var it = std.mem.split(u8, std.mem.trim(u8, stdout, " \n"), ",");
        const p_str = it.next() orelse return Value.None;
        const q_str = it.next() orelse return Value.None;
        const d_str = it.next() orelse return Value.None;
        
        var result = std.StringHashMap(Value).init(interp.allocator);
        try result.put("p", Value{ .String = p_str });
        try result.put("q", Value{ .String = q_str });
        try result.put("d", Value{ .String = d_str });
        try result.put("factored", Value{ .Bool = true });
        return Value{ .Dict = result };
    }
    
    var result = std.StringHashMap(Value).init(interp.allocator);
    try result.put("factored", Value{ .Bool = false });
    return Value{ .Dict = result };
}

// rsa_compute_d(p, q, e) - Compute private exponent d given p, q, e
pub fn builtin_rsa_compute_d(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 3) return Value.None;
    
    const p_str = switch (args[0]) {
        .String => |s| s,
        .Int => |i| try std.fmt.allocPrint(interp.allocator, "{}", .{i}),
        else => return Value.None,
    };
    
    const q_str = switch (args[1]) {
        .String => |s| s,
        .Int => |i| try std.fmt.allocPrint(interp.allocator, "{}", .{i}),
        else => return Value.None,
    };
    
    const e_str = switch (args[2]) {
        .String => |s| s,
        .Int => |i| try std.fmt.allocPrint(interp.allocator, "{}", .{i}),
        else => return Value.None,
    };
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\import sys
        \\p = int('{s}')
        \\q = int('{s}')
        \\e = int('{s}')
        \\phi = (p - 1) * (q - 1)
        \\d = pow(e, -1, phi)
        \\print(d)
    , .{ p_str, q_str, e_str });
    defer interp.allocator.free(script);
    
    const tmp_path = "/tmp/pc_compute_d.py";
    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return Value.None;
    defer file.close();
    file.writeAll(script) catch return Value.None;
    
    var child = std.process.Child.init(&[_][]const u8{ "python3", tmp_path }, interp.allocator);
    child.stdout_behavior = .Pipe;
    child.spawn() catch return Value.None;
    
    const stdout = child.stdout.?.reader().readAllAlloc(interp.allocator, 4096) catch return Value.None;
    _ = child.wait() catch return Value.None;
    
    const d_str = std.mem.trim(u8, stdout, " \n");
    return Value{ .String = d_str };
}

// rsa_decrypt_with_pqe(ciphertext, p, q, e) - Decrypt RSA ciphertext
pub fn builtin_rsa_decrypt_with_pqe(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 4) return Value.None;
    
    const c_str = switch (args[0]) {
        .String => |s| s,
        .Int => |i| try std.fmt.allocPrint(interp.allocator, "{}", .{i}),
        else => return Value.None,
    };
    
    const p_str = switch (args[1]) {
        .String => |s| s,
        .Int => |i| try std.fmt.allocPrint(interp.allocator, "{}", .{i}),
        else => return Value.None,
    };
    
    const q_str = switch (args[2]) {
        .String => |s| s,
        .Int => |i| try std.fmt.allocPrint(interp.allocator, "{}", .{i}),
        else => return Value.None,
    };
    
    const e_str = switch (args[3]) {
        .String => |s| s,
        .Int => |i| try std.fmt.allocPrint(interp.allocator, "{}", .{i}),
        else => return Value.None,
    };
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\import sys
        \\c = int('{s}')
        \\p = int('{s}')
        \\q = int('{s}')
        \\e = int('{s}')
        \\n = p * q
        \\phi = (p - 1) * (q - 1)
        \\d = pow(e, -1, phi)
        \\m = pow(c, d, n)
        \\print(m)
    , .{ c_str, p_str, q_str, e_str });
    defer interp.allocator.free(script);
    
    const tmp_path = "/tmp/pc_decrypt.py";
    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return Value.None;
    defer file.close();
    file.writeAll(script) catch return Value.None;
    
    var child = std.process.Child.init(&[_][]const u8{ "python3", tmp_path }, interp.allocator);
    child.stdout_behavior = .Pipe;
    child.spawn() catch return Value.None;
    
    const stdout = child.stdout.?.reader().readAllAlloc(interp.allocator, 4096) catch return Value.None;
    _ = child.wait() catch return Value.None;
    
    const m_str = std.mem.trim(u8, stdout, " \n");
    return Value{ .String = m_str };
}

// ============================================================================
// AES Encryption (using Python backend)
// ============================================================================

// aes_encrypt(plaintext, key, iv) - AES-128-CBC encryption
pub fn builtin_aes_encrypt(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 3 or args[0] != .String or args[1] != .String or args[2] != .String) return Value.None;
    
    const plaintext = args[0].String;
    const key = args[1].String;
    const iv = args[2].String;
    
    // Encode to hex for Python
    const pt_hex = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(plaintext)});
    defer interp.allocator.free(pt_hex);
    const key_hex = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(key)});
    defer interp.allocator.free(key_hex);
    const iv_hex = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(iv)});
    defer interp.allocator.free(iv_hex);
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\from Crypto.Cipher import AES
        \\from Crypto.Util.Padding import pad
        \\import binascii
        \\pt = binascii.unhexlify('{s}')
        \\key = binascii.unhexlify('{s}')
        \\iv = binascii.unhexlify('{s}')
        \\cipher = AES.new(key, AES.MODE_CBC, iv)
        \\ct = cipher.encrypt(pad(pt, AES.block_size))
        \\print(binascii.hexlify(ct).decode())
    , .{ pt_hex, key_hex, iv_hex });
    defer interp.allocator.free(script);
    
    const tmp_path = "/tmp/pc_aes_enc.py";
    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return Value.None;
    defer file.close();
    file.writeAll(script) catch return Value.None;
    
    var child = std.process.Child.init(&[_][]const u8{ "python3", tmp_path }, interp.allocator);
    child.stdout_behavior = .Pipe;
    child.spawn() catch return Value.None;
    
    const stdout = child.stdout.?.reader().readAllAlloc(interp.allocator, 8192) catch return Value.None;
    _ = child.wait() catch return Value.None;
    
    const ct_hex = std.mem.trim(u8, stdout, " \n");
    
    // Decode hex back to bytes
    const result = try interp.allocator.alloc(u8, ct_hex.len / 2);
    var i: usize = 0;
    while (i < ct_hex.len) : (i += 2) {
        result[i / 2] = std.fmt.parseInt(u8, ct_hex[i..i+2], 16) catch 0;
    }
    
    return Value{ .String = result };
}

// aes_decrypt(ciphertext, key, iv) - AES-128-CBC decryption
pub fn builtin_aes_decrypt(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 3 or args[0] != .String or args[1] != .String or args[2] != .String) return Value.None;
    
    const ciphertext = args[0].String;
    const key = args[1].String;
    const iv = args[2].String;
    
    const ct_hex = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(ciphertext)});
    defer interp.allocator.free(ct_hex);
    const key_hex = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(key)});
    defer interp.allocator.free(key_hex);
    const iv_hex = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(iv)});
    defer interp.allocator.free(iv_hex);
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\from Crypto.Cipher import AES
        \\from Crypto.Util.Padding import unpad
        \\import binascii
        \\ct = binascii.unhexlify('{s}')
        \\key = binascii.unhexlify('{s}')
        \\iv = binascii.unhexlify('{s}')
        \\cipher = AES.new(key, AES.MODE_CBC, iv)
        \\pt = unpad(cipher.decrypt(ct), AES.block_size)
        \\print(binascii.hexlify(pt).decode())
    , .{ ct_hex, key_hex, iv_hex });
    defer interp.allocator.free(script);
    
    const tmp_path = "/tmp/pc_aes_dec.py";
    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return Value.None;
    defer file.close();
    file.writeAll(script) catch return Value.None;
    
    var child = std.process.Child.init(&[_][]const u8{ "python3", tmp_path }, interp.allocator);
    child.stdout_behavior = .Pipe;
    child.spawn() catch return Value.None;
    
    const stdout = child.stdout.?.reader().readAllAlloc(interp.allocator, 8192) catch return Value.None;
    _ = child.wait() catch return Value.None;
    
    const pt_hex = std.mem.trim(u8, stdout, " \n");
    
    const result = try interp.allocator.alloc(u8, pt_hex.len / 2);
    var i: usize = 0;
    while (i < pt_hex.len) : (i += 2) {
        result[i / 2] = std.fmt.parseInt(u8, pt_hex[i..i+2], 16) catch 0;
    }
    
    return Value{ .String = result };
}

// ============================================================================
// File Operations
// ============================================================================

// read_file(path) - Read file as bytes
pub fn builtin_read_file(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value.None;
    
    const path = args[0].String;
    const file = std.fs.cwd().openFile(path, .{}) catch return Value.None;
    defer file.close();
    
    const content = file.readToEndAlloc(interp.allocator, 10 * 1024 * 1024) catch return Value.None;
    return Value{ .String = content };
}

// write_file(path, data) - Write bytes to file
pub fn builtin_write_file(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .String) return Value.None;
    
    const path = args[0].String;
    const data = args[1].String;
    
    const file = std.fs.cwd().createFile(path, .{}) catch return Value.None;
    defer file.close();
    
    file.writeAll(data) catch return Value.None;
    return Value{ .Bool = true };
}

// ============================================================================
// Shellcode Generation
// ============================================================================

// shellcode_execve(cmd) - Generate execve shellcode
pub fn builtin_shellcode_execve(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value.None;
    
    _ = args[0].String; // cmd parameter for future use
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\from pwn import *
        \\context.arch = 'amd64'
        \\sc = asm(shellcraft.amd64.linux.sh())
        \\print(sc.hex())
    , .{});
    defer interp.allocator.free(script);
    
    const tmp_path = "/tmp/pc_shellcode.py";
    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return Value.None;
    defer file.close();
    file.writeAll(script) catch return Value.None;
    
    var child = std.process.Child.init(&[_][]const u8{ "python3", tmp_path }, interp.allocator);
    child.stdout_behavior = .Pipe;
    child.spawn() catch return Value.None;
    
    const stdout = child.stdout.?.reader().readAllAlloc(interp.allocator, 8192) catch return Value.None;
    _ = child.wait() catch return Value.None;
    
    const sc_hex = std.mem.trim(u8, stdout, " \n");
    
    const result = try interp.allocator.alloc(u8, sc_hex.len / 2);
    var i: usize = 0;
    while (i < sc_hex.len) : (i += 2) {
        result[i / 2] = std.fmt.parseInt(u8, sc_hex[i..i+2], 16) catch 0;
    }
    
    return Value{ .String = result };
}

// ============================================================================
// CTF Utilities
// ============================================================================

// bytes_to_long(bytes) - Convert bytes to integer (big-endian)
pub fn builtin_bytes_to_long(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) return Value{ .Int = 0 };
    
    const bytes = args[0].String;
    const hex_str = try std.fmt.allocPrint(interp.allocator, "{x}", .{std.fmt.fmtSliceHexLower(bytes)});
    defer interp.allocator.free(hex_str);
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\import binascii
        \\data = binascii.unhexlify('{s}')
        \\result = int.from_bytes(data, 'big')
        \\print(result)
    , .{hex_str});
    defer interp.allocator.free(script);
    
    const tmp_path = "/tmp/pc_b2l.py";
    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return Value{ .Int = 0 };
    defer file.close();
    file.writeAll(script) catch return Value{ .Int = 0 };
    
    var child = std.process.Child.init(&[_][]const u8{ "python3", tmp_path }, interp.allocator);
    child.stdout_behavior = .Pipe;
    child.spawn() catch return Value{ .Int = 0 };
    
    const stdout = child.stdout.?.reader().readAllAlloc(interp.allocator, 4096) catch return Value{ .Int = 0 };
    _ = child.wait() catch return Value{ .Int = 0 };
    
    const num_str = std.mem.trim(u8, stdout, " \n");
    return Value{ .String = num_str };
}

// long_to_bytes(n) - Convert integer to bytes (big-endian)
pub fn builtin_long_to_bytes(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0) return Value{ .String = "" };
    
    const n_str = switch (args[0]) {
        .String => |s| s,
        .Int => |i| try std.fmt.allocPrint(interp.allocator, "{}", .{i}),
        else => return Value{ .String = "" },
    };
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\import binascii
        \\n = int('{s}')
        \\byte_len = (n.bit_length() + 7) // 8
        \\data = n.to_bytes(byte_len, 'big')
        \\print(binascii.hexlify(data).decode())
    , .{n_str});
    defer interp.allocator.free(script);
    
    const tmp_path = "/tmp/pc_l2b.py";
    const file = std.fs.cwd().createFile(tmp_path, .{}) catch return Value{ .String = "" };
    defer file.close();
    file.writeAll(script) catch return Value{ .String = "" };
    
    var child = std.process.Child.init(&[_][]const u8{ "python3", tmp_path }, interp.allocator);
    child.stdout_behavior = .Pipe;
    child.spawn() catch return Value{ .String = "" };
    
    const stdout = child.stdout.?.reader().readAllAlloc(interp.allocator, 8192) catch return Value{ .String = "" };
    _ = child.wait() catch return Value{ .String = "" };
    
    const hex_str = std.mem.trim(u8, stdout, " \n");
    
    const result = try interp.allocator.alloc(u8, hex_str.len / 2);
    var i: usize = 0;
    while (i < hex_str.len) : (i += 2) {
        result[i / 2] = std.fmt.parseInt(u8, hex_str[i..i+2], 16) catch 0;
    }
    
    return Value{ .String = result };
}
