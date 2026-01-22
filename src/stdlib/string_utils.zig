// PC Language - String Utilities Module
const std = @import("std");
const Interpreter = @import("../interpreter.zig").Interpreter;
const Value = @import("../interpreter.zig").Value;
const InterpreterError = @import("../interpreter.zig").InterpreterError;

// split(string, delimiter) - Split string by delimiter
pub fn builtin_split(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .String) {
        return Value.None;
    }
    
    const text = args[0].String;
    const delimiter = args[1].String;
    
    var result = std.ArrayList(Value).init(interp.allocator);
    
    if (delimiter.len == 0) {
        // Empty delimiter: split into characters
        for (text) |c| {
            const char_str = try interp.allocator.alloc(u8, 1);
            char_str[0] = c;
            try result.append(Value{ .String = char_str });
        }
    } else {
        var it = std.mem.splitSequence(u8, text, delimiter);
        while (it.next()) |part| {
            const part_copy = try interp.allocator.dupe(u8, part);
            try result.append(Value{ .String = part_copy });
        }
    }
    
    return Value{ .List = result };
}

// join(list, delimiter) - Join list elements with delimiter
pub fn builtin_join(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .List or args[1] != .String) {
        return Value{ .String = "" };
    }
    
    const list = args[0].List;
    const delimiter = args[1].String;
    
    if (list.items.len == 0) return Value{ .String = "" };
    
    var result = std.ArrayList(u8).init(interp.allocator);
    
    for (list.items, 0..) |item, i| {
        if (i > 0) {
            try result.appendSlice(delimiter);
        }
        
        // Convert item to string
        switch (item) {
            .String => |s| try result.appendSlice(s),
            .Int => |n| {
                const str = try std.fmt.allocPrint(interp.allocator, "{}", .{n});
                defer interp.allocator.free(str);
                try result.appendSlice(str);
            },
            else => try result.appendSlice("<object>"),
        }
    }
    
    return Value{ .String = try result.toOwnedSlice() };
}

// replace(string, old, new) - Replace all occurrences
pub fn builtin_replace(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 3 or args[0] != .String or args[1] != .String or args[2] != .String) {
        return Value{ .String = "" };
    }
    
    const text = args[0].String;
    const old = args[1].String;
    const new = args[2].String;
    
    if (old.len == 0) return Value{ .String = text };
    
    var result = std.ArrayList(u8).init(interp.allocator);
    
    var i: usize = 0;
    while (i < text.len) {
        if (i + old.len <= text.len and std.mem.eql(u8, text[i..i+old.len], old)) {
            try result.appendSlice(new);
            i += old.len;
        } else {
            try result.append(text[i]);
            i += 1;
        }
    }
    
    return Value{ .String = try result.toOwnedSlice() };
}

// strip(string) - Remove leading and trailing whitespace
pub fn builtin_strip(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .String = "" };
    }
    
    const text = args[0].String;
    const trimmed = std.mem.trim(u8, text, " \t\n\r");
    const result = try interp.allocator.dupe(u8, trimmed);
    
    return Value{ .String = result };
}

// startswith(string, prefix) - Check if string starts with prefix
pub fn builtin_startswith(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .String) {
        return Value{ .Bool = false };
    }
    
    const text = args[0].String;
    const prefix = args[1].String;
    
    if (prefix.len > text.len) return Value{ .Bool = false };
    
    return Value{ .Bool = std.mem.eql(u8, text[0..prefix.len], prefix) };
}

// endswith(string, suffix) - Check if string ends with suffix
pub fn builtin_endswith(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .String) {
        return Value{ .Bool = false };
    }
    
    const text = args[0].String;
    const suffix = args[1].String;
    
    if (suffix.len > text.len) return Value{ .Bool = false };
    
    return Value{ .Bool = std.mem.eql(u8, text[text.len - suffix.len..], suffix) };
}

// find(string, substring) - Find first occurrence position (returns -1 if not found)
pub fn builtin_find(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .String) {
        return Value{ .Int = -1 };
    }
    
    const text = args[0].String;
    const substring = args[1].String;
    
    if (substring.len == 0) return Value{ .Int = 0 };
    if (substring.len > text.len) return Value{ .Int = -1 };
    
    var i: usize = 0;
    while (i <= text.len - substring.len) : (i += 1) {
        if (std.mem.eql(u8, text[i..i+substring.len], substring)) {
            return Value{ .Int = @intCast(i) };
        }
    }
    
    return Value{ .Int = -1 };
}

// chr(n) - Convert ASCII code to character
pub fn builtin_chr(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .Int) {
        return Value{ .String = "" };
    }
    
    const code = args[0].Int;
    if (code < 0 or code > 255) return Value{ .String = "" };
    
    const result = try interp.allocator.alloc(u8, 1);
    result[0] = @intCast(code);
    
    return Value{ .String = result };
}

// ord(char) - Convert character to ASCII code
pub fn builtin_ord(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .Int = 0 };
    }
    
    const text = args[0].String;
    if (text.len == 0) return Value{ .Int = 0 };
    
    return Value{ .Int = @intCast(text[0]) };
}

// bin(n) - Convert integer to binary string
pub fn builtin_bin(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .Int) {
        return Value{ .String = "0b0" };
    }
    
    const n = args[0].Int;
    const result = try std.fmt.allocPrint(interp.allocator, "0b{b}", .{n});
    
    return Value{ .String = result };
}

// oct(n) - Convert integer to octal string
pub fn builtin_oct(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .Int) {
        return Value{ .String = "0o0" };
    }
    
    const n = args[0].Int;
    const result = try std.fmt.allocPrint(interp.allocator, "0o{o}", .{n});
    
    return Value{ .String = result };
}

// unhex(hex_string) - Convert hex string to integer
pub fn builtin_unhex(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .Int = 0 };
    }
    
    var hex_str = args[0].String;
    
    // Remove 0x prefix if present
    if (hex_str.len > 2 and std.mem.eql(u8, hex_str[0..2], "0x")) {
        hex_str = hex_str[2..];
    }
    
    const result = std.fmt.parseInt(i64, hex_str, 16) catch 0;
    
    return Value{ .Int = result };
}
