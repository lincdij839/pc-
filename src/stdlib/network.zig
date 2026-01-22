// PC Language - Network Module (CTF)
const std = @import("std");
const Interpreter = @import("../interpreter.zig").Interpreter;
const Value = @import("../interpreter.zig").Value;
const InterpreterError = @import("../interpreter.zig").InterpreterError;

pub const SocketHandle = struct {
    stream: std.net.Stream,
    allocator: std.mem.Allocator,
    
    pub fn initConnect(allocator: std.mem.Allocator, host: []const u8, port: u16) !SocketHandle {
        const address = try std.net.Address.parseIp4(host, port);
        const stream = try std.net.tcpConnectToAddress(address);
        
        return SocketHandle{
            .stream = stream,
            .allocator = allocator,
        };
    }
    
    pub fn initListen(allocator: std.mem.Allocator, port: u16) !SocketHandle {
        const address = try std.net.Address.parseIp4("0.0.0.0", port);
        var listener = try address.listen(.{ .reuse_address = true });
        const conn = try listener.accept();
        
        return SocketHandle{
            .stream = conn.stream,
            .allocator = allocator,
        };
    }
    
    pub fn send(self: *SocketHandle, data: []const u8) !void {
        _ = try self.stream.write(data);
    }
    
    pub fn sendline(self: *SocketHandle, data: []const u8) !void {
        try self.send(data);
        try self.send("\n");
    }
    
    pub fn recv(self: *SocketHandle, size: usize) ![]u8 {
        const buffer = try self.allocator.alloc(u8, size);
        const bytes_read = try self.stream.read(buffer);
        return buffer[0..bytes_read];
    }
    
    pub fn recvline(self: *SocketHandle) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        while (true) {
            var byte: [1]u8 = undefined;
            const bytes_read = try self.stream.read(&byte);
            if (bytes_read == 0) break;
            try buffer.append(byte[0]);
            if (byte[0] == '\n') break;
        }
        return buffer.toOwnedSlice();
    }
    
    pub fn recvuntil(self: *SocketHandle, delimiter: []const u8) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        while (true) {
            var byte: [1]u8 = undefined;
            const bytes_read = try self.stream.read(&byte);
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
        return buffer.toOwnedSlice();
    }
    
    pub fn sendafter(self: *SocketHandle, delimiter: []const u8, data: []const u8) !void {
        _ = try self.recvuntil(delimiter);
        try self.send(data);
    }
    
    pub fn close(self: *SocketHandle) void {
        self.stream.close();
    }
};

// Builtin: remote(host, port) - Connect to remote TCP server
pub fn builtin_remote(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value.None;
    if (args[0] != .String or args[1] != .Int) return Value.None;
    
    const host = args[0].String;
    const port: u16 = @intCast(args[1].Int);
    
    const handle_ptr = try interp.allocator.create(SocketHandle);
    handle_ptr.* = SocketHandle.initConnect(interp.allocator, host, port) catch return InterpreterError.RuntimeError;
    
    return Value{ .Socket = handle_ptr };
}

// Builtin: listen(port) - Listen on TCP port
pub fn builtin_listen(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 1) return Value.None;
    if (args[0] != .Int) return Value.None;
    
    const port: u16 = @intCast(args[0].Int);
    
    const handle_ptr = try interp.allocator.create(SocketHandle);
    handle_ptr.* = SocketHandle.initListen(interp.allocator, port) catch return InterpreterError.RuntimeError;
    
    return Value{ .Socket = handle_ptr };
}

// Socket method: send(data)
pub fn builtin_sock_send(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value.None;
    if (args[0] != .Socket or args[1] != .String) return Value.None;
    
    const handle: *SocketHandle = @ptrCast(@alignCast(args[0].Socket));
    handle.send(args[1].String) catch return InterpreterError.RuntimeError;
    return Value.None;
}

// Socket method: sendline(data)
pub fn builtin_sock_sendline(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value.None;
    if (args[0] != .Socket or args[1] != .String) return Value.None;
    
    const handle: *SocketHandle = @ptrCast(@alignCast(args[0].Socket));
    handle.sendline(args[1].String) catch return InterpreterError.RuntimeError;
    return Value.None;
}

// Socket method: recv(size)
pub fn builtin_sock_recv(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value.None;
    if (args[0] != .Socket or args[1] != .Int) return Value.None;
    
    const handle: *SocketHandle = @ptrCast(@alignCast(args[0].Socket));
    const data = handle.recv(@intCast(args[1].Int)) catch return InterpreterError.RuntimeError;
    return Value{ .String = data };
}

// Socket method: recvline()
pub fn builtin_sock_recvline(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 1) return Value.None;
    if (args[0] != .Socket) return Value.None;
    
    const handle: *SocketHandle = @ptrCast(@alignCast(args[0].Socket));
    const data = handle.recvline() catch return InterpreterError.RuntimeError;
    return Value{ .String = data };
}

// Socket method: recvuntil(delimiter)
pub fn builtin_sock_recvuntil(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2) return Value.None;
    if (args[0] != .Socket or args[1] != .String) return Value.None;
    
    const handle: *SocketHandle = @ptrCast(@alignCast(args[0].Socket));
    const data = handle.recvuntil(args[1].String) catch return InterpreterError.RuntimeError;
    return Value{ .String = data };
}

// Socket method: sendafter(delimiter, data)
pub fn builtin_sock_sendafter(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 3) return Value.None;
    if (args[0] != .Socket or args[1] != .String or args[2] != .String) return Value.None;
    
    const handle: *SocketHandle = @ptrCast(@alignCast(args[0].Socket));
    handle.sendafter(args[1].String, args[2].String) catch return InterpreterError.RuntimeError;
    return Value.None;
}
