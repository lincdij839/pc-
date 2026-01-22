// PC Language Standard Library - Built-in Functions (Refactored)
const std = @import("std");
const Interpreter = @import("../interpreter.zig").Interpreter;
const Value = @import("../interpreter.zig").Value;
const InterpreterError = @import("../interpreter.zig").InterpreterError;

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
