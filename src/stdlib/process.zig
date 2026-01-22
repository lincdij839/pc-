// PC Language - Process Module (PWN)
const std = @import("std");
const Interpreter = @import("../interpreter.zig").Interpreter;
const Value = @import("../interpreter.zig").Value;
const InterpreterError = @import("../interpreter.zig").InterpreterError;

pub const ProcessHandle = struct {
    child: std.process.Child,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, program: []const u8, args: []const []const u8) !ProcessHandle {
        _ = program; // 未使用但保留用于日志
        var child = std.process.Child.init(args, allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;
        
        try child.spawn();
        
        return ProcessHandle{
            .child = child,
            .allocator = allocator,
        };
    }
    
    pub fn send(self: *ProcessHandle, data: []const u8) !void {
        if (self.child.stdin) |stdin| {
            try stdin.writeAll(data);
        }
    }
    
    pub fn sendline(self: *ProcessHandle, data: []const u8) !void {
        try self.send(data);
        try self.send("\n");
    }
    
    pub fn recv(self: *ProcessHandle, size: usize) ![]u8 {
        if (self.child.stdout) |stdout| {
            const buffer = try self.allocator.alloc(u8, size);
            const bytes_read = try stdout.read(buffer);
            return buffer[0..bytes_read];
        }
        return error.NoStdout;
    }
    
    pub fn recvline(self: *ProcessHandle) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        if (self.child.stdout) |stdout| {
            while (true) {
                var byte: [1]u8 = undefined;
                const bytes_read = try stdout.read(&byte);
                if (bytes_read == 0) break;
                try buffer.append(byte[0]);
                if (byte[0] == '\n') break;
            }
        }
        return buffer.toOwnedSlice();
    }
    
    pub fn recvuntil(self: *ProcessHandle, delimiter: []const u8) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        if (self.child.stdout) |stdout| {
            while (true) {
                var byte: [1]u8 = undefined;
                const bytes_read = try stdout.read(&byte);
                if (bytes_read == 0) break;
                try buffer.append(byte[0]);
                
                // Check if buffer ends with delimiter
                if (buffer.items.len >= delimiter.len) {
                    const end_slice = buffer.items[buffer.items.len - delimiter.len..];
                    if (std.mem.eql(u8, end_slice, delimiter)) {
                        break;
                    }
                }
            }
        }
        return buffer.toOwnedSlice();
    }
    
    pub fn sendafter(self: *ProcessHandle, delimiter: []const u8, data: []const u8) !void {
        _ = try self.recvuntil(delimiter);
        try self.send(data);
    }
    
    pub fn interactive(self: *ProcessHandle) !void {
        const stdin = std.io.getStdIn();
        const stdout = std.io.getStdOut();
        
        var buffer: [1024]u8 = undefined;
        
        // Simple interactive mode: forward stdin to process, process output to stdout
        while (true) {
            // Check if there's data from process
            if (self.child.stdout) |proc_stdout| {
                const bytes_read = proc_stdout.read(&buffer) catch break;
                if (bytes_read > 0) {
                    try stdout.writeAll(buffer[0..bytes_read]);
                }
            }
            
            // Check if there's data from user stdin
            const user_input = stdin.read(&buffer) catch break;
            if (user_input > 0) {
                try self.send(buffer[0..user_input]);
            } else {
                break;
            }
        }
    }
    
    pub fn close(self: *ProcessHandle) !void {
        _ = try self.child.wait();
    }
};

// Builtin functions for PC Language
pub fn builtin_process(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0) return Value.None;
    if (args[0] != .String) return Value.None;
    
    const program = args[0].String;
    
    // Parse additional arguments
    var argv = std.ArrayList([]const u8).init(interp.allocator);
    try argv.append(program);
    
    for (args[1..]) |arg| {
        if (arg == .String) {
            try argv.append(arg.String);
        }
    }
    
    const handle_ptr = try interp.allocator.create(ProcessHandle);
    handle_ptr.* = ProcessHandle.init(interp.allocator, program, argv.items) catch return InterpreterError.RuntimeError;
    
    return Value{ .Process = handle_ptr };
}

// Process method: send(data)
pub fn builtin_proc_send(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value.None;
    if (args[0] != .Process or args[1] != .String) return Value.None;
    
    const handle: *ProcessHandle = @ptrCast(@alignCast(args[0].Process));
    handle.send(args[1].String) catch return InterpreterError.RuntimeError;
    return Value.None;
}

// Process method: sendline(data)
pub fn builtin_proc_sendline(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value.None;
    if (args[0] != .Process or args[1] != .String) return Value.None;
    
    const handle: *ProcessHandle = @ptrCast(@alignCast(args[0].Process));
    handle.sendline(args[1].String) catch return InterpreterError.RuntimeError;
    return Value.None;
}

// Process method: recv(size)
pub fn builtin_proc_recv(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value.None;
    if (args[0] != .Process or args[1] != .Int) return Value.None;
    
    const handle: *ProcessHandle = @ptrCast(@alignCast(args[0].Process));
    const data = handle.recv(@intCast(args[1].Int)) catch return InterpreterError.RuntimeError;
    return Value{ .String = data };
}

// Process method: recvline()
pub fn builtin_proc_recvline(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 1) return Value.None;
    if (args[0] != .Process) return Value.None;
    
    const handle: *ProcessHandle = @ptrCast(@alignCast(args[0].Process));
    const data = handle.recvline() catch return InterpreterError.RuntimeError;
    return Value{ .String = data };
}

// Process method: recvuntil(delimiter)
pub fn builtin_proc_recvuntil(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value.None;
    if (args[0] != .Process or args[1] != .String) return Value.None;
    
    const handle: *ProcessHandle = @ptrCast(@alignCast(args[0].Process));
    const data = handle.recvuntil(args[1].String) catch return InterpreterError.RuntimeError;
    return Value{ .String = data };
}

// Process method: sendafter(delimiter, data)
pub fn builtin_proc_sendafter(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 3) return Value.None;
    if (args[0] != .Process or args[1] != .String or args[2] != .String) return Value.None;
    
    const handle: *ProcessHandle = @ptrCast(@alignCast(args[0].Process));
    handle.sendafter(args[1].String, args[2].String) catch return InterpreterError.RuntimeError;
    return Value.None;
}

// Process method: interactive()
pub fn builtin_proc_interactive(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 1) return Value.None;
    if (args[0] != .Process) return Value.None;
    
    const handle: *ProcessHandle = @ptrCast(@alignCast(args[0].Process));
    handle.interactive() catch return InterpreterError.RuntimeError;
    return Value.None;
}
