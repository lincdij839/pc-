// PC Language - Attack & Defense Module
const std = @import("std");
const Interpreter = @import("../interpreter.zig").Interpreter;
const Value = @import("../interpreter.zig").Value;
const InterpreterError = @import("../interpreter.zig").InterpreterError;

// ============================================================================
// Port Scanning
// ============================================================================

// scan_port(host, port) - Scan single port
pub fn builtin_scan_port(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .Int) {
        return Value{ .Bool = false };
    }
    
    const host = args[0].String;
    const port: u16 = @intCast(args[1].Int);
    
    // Try to connect with timeout
    const address = std.net.Address.parseIp4(host, port) catch 
        return Value{ .Bool = false };
    
    const stream = std.net.tcpConnectToAddress(address) catch 
        return Value{ .Bool = false };
    
    stream.close();
    return Value{ .Bool = true };
}

// scan_ports(host, ports) - Scan multiple ports
pub fn builtin_scan_ports(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .List) {
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    }
    
    const host = args[0].String;
    const ports = args[1].List;
    
    var open_ports = std.ArrayList(Value).init(interp.allocator);
    
    for (ports.items) |port_val| {
        if (port_val == .Int) {
            const port: u16 = @intCast(port_val.Int);
            
            const address = std.net.Address.parseIp4(host, port) catch continue;
            const stream = std.net.tcpConnectToAddress(address) catch continue;
            stream.close();
            
            try open_ports.append(Value{ .Int = port_val.Int });
        }
    }
    
    return Value{ .List = open_ports };
}

// scan_common_ports(host) - Scan common service ports
pub fn builtin_scan_common_ports(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    }
    
    const host = args[0].String;
    
    // Common ports to scan
    const common_ports = [_]u16{
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
        3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017
    };
    
    var open_ports = std.ArrayList(Value).init(interp.allocator);
    
    for (common_ports) |port| {
        const address = std.net.Address.parseIp4(host, port) catch continue;
        const stream = std.net.tcpConnectToAddress(address) catch continue;
        stream.close();
        
        try open_ports.append(Value{ .Int = @intCast(port) });
    }
    
    return Value{ .List = open_ports };
}

// ============================================================================
// Banner Grabbing
// ============================================================================

// get_banner(host, port, timeout) - Grab service banner
pub fn builtin_get_banner(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .Int) {
        return Value{ .String = "" };
    }
    
    const host = args[0].String;
    const port: u16 = @intCast(args[1].Int);
    
    const address = std.net.Address.parseIp4(host, port) catch 
        return Value{ .String = "Connection failed" };
    
    const stream = std.net.tcpConnectToAddress(address) catch 
        return Value{ .String = "Connection failed" };
    defer stream.close();
    
    // Read banner (first 1024 bytes)
    var buffer: [1024]u8 = undefined;
    const bytes_read = stream.read(&buffer) catch 0;
    
    if (bytes_read > 0) {
        const banner = try interp.allocator.dupe(u8, buffer[0..bytes_read]);
        return Value{ .String = banner };
    }
    
    return Value{ .String = "No banner" };
}

// ============================================================================
// Service Detection
// ============================================================================

// detect_service(host, port) - Detect service type
pub fn builtin_detect_service(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .Int) {
        return Value{ .String = "unknown" };
    }
    
    const port: u16 = @intCast(args[1].Int);
    
    // Common port-to-service mapping
    const service = switch (port) {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8080 => "HTTP-Proxy",
        8443 => "HTTPS-Alt",
        27017 => "MongoDB",
        else => "Unknown",
    };
    
    const result = try interp.allocator.dupe(u8, service);
    return Value{ .String = result };
}

// ============================================================================
// Vulnerability Checking
// ============================================================================

// check_vuln_sql(url) - Quick SQL injection check
pub fn builtin_check_vuln_sql(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .Bool = false };
    }
    
    const url = args[0].String;
    
    // Add SQL injection test payloads
    const payloads = [_][]const u8{
        "'", "\"", "1' OR '1'='1", "' OR 1=1--", "admin'--"
    };
    
    for (payloads) |payload| {
        const test_url = std.fmt.allocPrint(interp.allocator, "{s}{s}", .{url, payload}) catch continue;
        defer interp.allocator.free(test_url);
        
        // Use curl to test (simple detection)
        const script = std.fmt.allocPrint(interp.allocator,
            \\curl -s -o /dev/null -w '%{{http_code}}' '{s}' 2>/dev/null
        , .{test_url}) catch continue;
        defer interp.allocator.free(script);
        
        const result = executeShellCommand(interp.allocator, script) catch continue;
        defer interp.allocator.free(result);
        
        // Check for SQL error indicators
        const trimmed = std.mem.trim(u8, result, " \t\r\n");
        if (std.mem.eql(u8, trimmed, "500")) {
            return Value{ .Bool = true }; // Possible SQL injection
        }
    }
    
    return Value{ .Bool = false };
}

// check_vuln_xss(url) - Quick XSS check
pub fn builtin_check_vuln_xss(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .Bool = false };
    }
    
    const url = args[0].String;
    
    const test_payload = "<script>alert(1)</script>";
    const test_url = std.fmt.allocPrint(interp.allocator, "{s}{s}", .{url, test_payload}) catch 
        return Value{ .Bool = false };
    defer interp.allocator.free(test_url);
    
    const script = std.fmt.allocPrint(interp.allocator,
        \\curl -s '{s}' 2>/dev/null | grep -q '<script>alert(1)</script>' && echo 'vulnerable' || echo 'safe'
    , .{test_url}) catch return Value{ .Bool = false };
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .Bool = false };
    defer interp.allocator.free(result);
    
    const trimmed = std.mem.trim(u8, result, " \t\r\n");
    return Value{ .Bool = std.mem.eql(u8, trimmed, "vulnerable") };
}

// ============================================================================
// Network Information
// ============================================================================

// ping(host, count) - Ping host
pub fn builtin_ping(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .Bool = false };
    }
    
    const host = args[0].String;
    var count: i64 = 4;
    if (args.len >= 2 and args[1] == .Int) {
        count = args[1].Int;
    }
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\ping -c {d} {s} >/dev/null 2>&1 && echo 'alive' || echo 'dead'
    , .{count, host});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .Bool = false };
    defer interp.allocator.free(result);
    
    const trimmed = std.mem.trim(u8, result, " \t\r\n");
    return Value{ .Bool = std.mem.eql(u8, trimmed, "alive") };
}

// traceroute(host) - Trace route to host
pub fn builtin_traceroute(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .String = "" };
    }
    
    const host = args[0].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\traceroute -m 15 {s} 2>/dev/null | head -20
    , .{host});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .String = "traceroute failed" };
    
    return Value{ .String = result };
}

// ============================================================================
// Packet Crafting Helpers
// ============================================================================

// craft_tcp_syn(dst_ip, dst_port) - Generate TCP SYN packet info
pub fn builtin_craft_tcp_syn(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .Int) {
        return Value.None;
    }
    
    const dst_ip = args[0].String;
    const dst_port = args[1].Int;
    
    var result = std.StringHashMap(Value).init(interp.allocator);
    
    try result.put("type", Value{ .String = try interp.allocator.dupe(u8, "TCP-SYN") });
    try result.put("dst_ip", Value{ .String = try interp.allocator.dupe(u8, dst_ip) });
    try result.put("dst_port", Value{ .Int = dst_port });
    try result.put("flags", Value{ .String = try interp.allocator.dupe(u8, "SYN") });
    
    return Value{ .Dict = result };
}

// ============================================================================
// Attack Simulation
// ============================================================================

// simulate_ddos(target, connections) - Simulate DDoS (educational only!)
pub fn builtin_simulate_ddos(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .Int) {
        return Value{ .String = "Invalid arguments" };
    }
    
    // IMPORTANT: For educational purposes only!
    // DO NOT use for actual attacks
    const warning = try interp.allocator.dupe(u8, 
        "WARNING: DDoS simulation disabled for safety. Educational only!");
    
    return Value{ .String = warning };
}

// ============================================================================
// Defense Tools
// ============================================================================

// detect_port_scan(log_file) - Detect port scanning in logs
pub fn builtin_detect_port_scan(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    }
    
    const log_file = args[0].String;
    
    // Look for rapid connection attempts (indicator of port scan)
    const script = try std.fmt.allocPrint(interp.allocator,
        \\cat '{s}' 2>/dev/null | grep -E 'SYN|connection' | awk '{{print $1}}' | sort | uniq -c | sort -nr | head -10
    , .{log_file});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    
    var suspicious = std.ArrayList(Value).init(interp.allocator);
    var it = std.mem.splitScalar(u8, result, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 0) {
            const entry = try interp.allocator.dupe(u8, trimmed);
            try suspicious.append(Value{ .String = entry });
        }
    }
    
    return Value{ .List = suspicious };
}

// block_ip(ip_address) - Generate iptables block command
pub fn builtin_block_ip(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .String = "" };
    }
    
    const ip = args[0].String;
    
    const cmd = try std.fmt.allocPrint(interp.allocator,
        "iptables -A INPUT -s {s} -j DROP",
        .{ip}
    );
    
    return Value{ .String = cmd };
}

// ============================================================================
// Rate Limiting & Throttling
// ============================================================================

// check_rate_limit(ip, max_requests, window) - Simple rate limit check
pub fn builtin_check_rate_limit(_: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 3 or args[0] != .String or args[1] != .Int or args[2] != .Int) {
        return Value{ .Bool = true }; // Allow by default
    }
    
    // This is a placeholder - in real implementation, would track actual requests
    // For demonstration: simulate allowing the request
    return Value{ .Bool = true };
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
