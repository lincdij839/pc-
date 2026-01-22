// PC Language - OSINT (Open Source Intelligence) Module
const std = @import("std");
const Interpreter = @import("../interpreter.zig").Interpreter;
const Value = @import("../interpreter.zig").Value;
const InterpreterError = @import("../interpreter.zig").InterpreterError;

// ============================================================================
// DNS Enumeration
// ============================================================================

// dns_lookup(domain, record_type) - DNS record lookup
// record_type: "A", "AAAA", "MX", "NS", "TXT", "CNAME"
pub fn builtin_dns_lookup(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .String) {
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    }
    
    const domain = args[0].String;
    const record_type = args[1].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\dig +short {s} {s} 2>/dev/null | head -20
    , .{domain, record_type});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    
    var records = std.ArrayList(Value).init(interp.allocator);
    var it = std.mem.splitScalar(u8, result, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 0) {
            const record = try interp.allocator.dupe(u8, trimmed);
            try records.append(Value{ .String = record });
        }
    }
    
    return Value{ .List = records };
}

// whois(domain_or_ip) - Whois query
pub fn builtin_whois(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .String = "" };
    }
    
    const target = args[0].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\whois {s} 2>/dev/null | head -50
    , .{target});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .String = "whois command failed" };
    
    return Value{ .String = result };
}

// subdomain_enum(domain, wordlist) - Basic subdomain enumeration
pub fn builtin_subdomain_enum(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .List) {
        return Value{ .List = std.ArrayList(Value).init(interp.allocator) };
    }
    
    const domain = args[0].String;
    const wordlist = args[1].List;
    
    var found_subdomains = std.ArrayList(Value).init(interp.allocator);
    
    // Test each subdomain
    for (wordlist.items) |word_val| {
        if (word_val != .String) continue;
        const subdomain = try std.fmt.allocPrint(
            interp.allocator,
            "{s}.{s}",
            .{word_val.String, domain}
        );
        defer interp.allocator.free(subdomain);
        
        // Try DNS lookup
        const script = try std.fmt.allocPrint(interp.allocator,
            \\host {s} 2>/dev/null | grep -q "has address" && echo "{s}"
        , .{subdomain, subdomain});
        defer interp.allocator.free(script);
        
        const result = executeShellCommand(interp.allocator, script) catch continue;
        defer interp.allocator.free(result);
        
        const trimmed = std.mem.trim(u8, result, " \t\r\n");
        if (trimmed.len > 0) {
            const found = try interp.allocator.dupe(u8, trimmed);
            try found_subdomains.append(Value{ .String = found });
        }
    }
    
    return Value{ .List = found_subdomains };
}

// ============================================================================
// IP Geolocation
// ============================================================================

// geoip(ip_address) - IP geolocation lookup
pub fn builtin_geoip(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value.None;
    }
    
    const ip = args[0].String;
    
    // Use ip-api.com free API
    const script = try std.fmt.allocPrint(interp.allocator,
        \\curl -s "http://ip-api.com/json/{s}?fields=status,country,countryCode,region,city,lat,lon,isp,org" 2>/dev/null
    , .{ip});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .String = "GeoIP lookup failed" };
    
    // Simple JSON parsing - extract key fields
    var info = std.StringHashMap(Value).init(interp.allocator);
    
    // Extract country
    if (std.mem.indexOf(u8, result, "\"country\":\"")) |idx| {
        const start = idx + 11;
        if (std.mem.indexOfPos(u8, result, start, "\"")) |end| {
            const country = try interp.allocator.dupe(u8, result[start..end]);
            try info.put("country", Value{ .String = country });
        }
    }
    
    // Extract city
    if (std.mem.indexOf(u8, result, "\"city\":\"")) |idx| {
        const start = idx + 8;
        if (std.mem.indexOfPos(u8, result, start, "\"")) |end| {
            const city = try interp.allocator.dupe(u8, result[start..end]);
            try info.put("city", Value{ .String = city });
        }
    }
    
    // Extract ISP
    if (std.mem.indexOf(u8, result, "\"isp\":\"")) |idx| {
        const start = idx + 7;
        if (std.mem.indexOfPos(u8, result, start, "\"")) |end| {
            const isp = try interp.allocator.dupe(u8, result[start..end]);
            try info.put("isp", Value{ .String = isp });
        }
    }
    
    // Store raw response
    try info.put("raw", Value{ .String = result });
    
    return Value{ .Dict = info };
}

// ============================================================================
// Email & Username Intelligence
// ============================================================================

// email_verify(email) - Basic email format validation and domain check
pub fn builtin_email_verify(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .Bool = false };
    }
    
    const email = args[0].String;
    
    // Basic format check
    if (std.mem.indexOf(u8, email, "@") == null) {
        return Value{ .Bool = false };
    }
    
    const at_pos = std.mem.indexOf(u8, email, "@").?;
    if (at_pos == 0 or at_pos == email.len - 1) {
        return Value{ .Bool = false };
    }
    
    const domain = email[at_pos + 1..];
    
    // Check if domain has MX records
    const script = try std.fmt.allocPrint(interp.allocator,
        \\dig +short MX {s} 2>/dev/null | grep -q "." && echo "valid" || echo "invalid"
    , .{domain});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .Bool = false };
    defer interp.allocator.free(result);
    
    const trimmed = std.mem.trim(u8, result, " \t\r\n");
    return Value{ .Bool = std.mem.eql(u8, trimmed, "valid") };
}

// username_search(username, platforms) - Search username across platforms
pub fn builtin_username_search(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .List) {
        return Value{ .Dict = std.StringHashMap(Value).init(interp.allocator) };
    }
    
    const username = args[0].String;
    const platforms = args[1].List;
    
    var results = std.StringHashMap(Value).init(interp.allocator);
    
    // Common platform URL patterns
    const platform_urls = [_]struct{ name: []const u8, url: []const u8 }{
        .{ .name = "github", .url = "https://github.com/{s}" },
        .{ .name = "twitter", .url = "https://twitter.com/{s}" },
        .{ .name = "reddit", .url = "https://www.reddit.com/user/{s}" },
        .{ .name = "instagram", .url = "https://www.instagram.com/{s}" },
        .{ .name = "linkedin", .url = "https://www.linkedin.com/in/{s}" },
    };
    
    for (platforms.items) |platform_val| {
        if (platform_val != .String) continue;
        const platform = platform_val.String;
        
        // Find URL pattern
        var url_pattern: ?[]const u8 = null;
        for (platform_urls) |p| {
            if (std.mem.eql(u8, p.name, platform)) {
                url_pattern = p.url;
                break;
            }
        }
        
        if (url_pattern) |pattern| {
            // Build URL manually to avoid comptime issues
            var url_buf = std.ArrayList(u8).init(interp.allocator);
            defer url_buf.deinit();
            
            // Replace {s} with username
            var i: usize = 0;
            while (i < pattern.len) : (i += 1) {
                if (i + 2 < pattern.len and pattern[i] == '{' and pattern[i+1] == 's' and pattern[i+2] == '}') {
                    try url_buf.appendSlice(username);
                    i += 2;
                } else {
                    try url_buf.append(pattern[i]);
                }
            }
            const url = try url_buf.toOwnedSlice();
            defer interp.allocator.free(url);
            
            // Check if profile exists (HTTP HEAD request)
            const script = try std.fmt.allocPrint(interp.allocator,
                \\curl -s -o /dev/null -w "%{{http_code}}" -L "{s}" 2>/dev/null
            , .{url});
            defer interp.allocator.free(script);
            
            const result = executeShellCommand(interp.allocator, script) catch continue;
            defer interp.allocator.free(result);
            
            const trimmed = std.mem.trim(u8, result, " \t\r\n");
            const exists = std.mem.eql(u8, trimmed, "200");
            
            const url_copy = try interp.allocator.dupe(u8, url);
            try results.put(platform, Value{ .String = if (exists) url_copy else "not_found" });
        }
    }
    
    return Value{ .Dict = results };
}

// ============================================================================
// Web Intelligence
// ============================================================================

// google_dork(keyword, site, filetype) - Generate Google Dork query
pub fn builtin_google_dork(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0) {
        return Value{ .String = "" };
    }
    
    var dork = std.ArrayList(u8).init(interp.allocator);
    
    // Keyword
    if (args.len > 0 and args[0] == .String) {
        try dork.appendSlice(args[0].String);
    }
    
    // Site filter
    if (args.len > 1 and args[1] == .String and args[1].String.len > 0) {
        try dork.appendSlice(" site:");
        try dork.appendSlice(args[1].String);
    }
    
    // Filetype filter
    if (args.len > 2 and args[2] == .String and args[2].String.len > 0) {
        try dork.appendSlice(" filetype:");
        try dork.appendSlice(args[2].String);
    }
    
    return Value{ .String = try dork.toOwnedSlice() };
}

// wayback_check(url) - Check if URL exists in Wayback Machine
pub fn builtin_wayback_check(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .Bool = false };
    }
    
    const url = args[0].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\curl -s "http://archive.org/wayback/available?url={s}" 2>/dev/null | grep -q '"available": true' && echo "yes" || echo "no"
    , .{url});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .Bool = false };
    defer interp.allocator.free(result);
    
    const trimmed = std.mem.trim(u8, result, " \t\r\n");
    return Value{ .Bool = std.mem.eql(u8, trimmed, "yes") };
}

// http_headers(url) - Fetch HTTP headers
pub fn builtin_http_headers(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .Dict = std.StringHashMap(Value).init(interp.allocator) };
    }
    
    const url = args[0].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\curl -s -I "{s}" 2>/dev/null | head -20
    , .{url});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .Dict = std.StringHashMap(Value).init(interp.allocator) };
    
    var headers = std.StringHashMap(Value).init(interp.allocator);
    
    var it = std.mem.splitScalar(u8, result, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        
        if (std.mem.indexOf(u8, trimmed, ":")) |colon_pos| {
            const key = std.mem.trim(u8, trimmed[0..colon_pos], " \t");
            const value = std.mem.trim(u8, trimmed[colon_pos + 1..], " \t");
            
            const key_copy = try interp.allocator.dupe(u8, key);
            const value_copy = try interp.allocator.dupe(u8, value);
            try headers.put(key_copy, Value{ .String = value_copy });
        }
    }
    
    return Value{ .Dict = headers };
}

// ============================================================================
// Certificate & SSL Intelligence
// ============================================================================

// ssl_cert_info(domain) - Get SSL certificate information
pub fn builtin_ssl_cert_info(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .Dict = std.StringHashMap(Value).init(interp.allocator) };
    }
    
    const domain = args[0].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\echo | openssl s_client -connect {s}:443 -servername {s} 2>/dev/null | openssl x509 -noout -text 2>/dev/null | head -30
    , .{domain, domain});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .Dict = std.StringHashMap(Value).init(interp.allocator) };
    
    var cert_info = std.StringHashMap(Value).init(interp.allocator);
    
    // Extract issuer
    if (std.mem.indexOf(u8, result, "Issuer:")) |idx| {
        const line_end = std.mem.indexOfPos(u8, result, idx, "\n") orelse result.len;
        const issuer = std.mem.trim(u8, result[idx + 7..line_end], " \t");
        try cert_info.put("issuer", Value{ .String = try interp.allocator.dupe(u8, issuer) });
    }
    
    // Extract subject
    if (std.mem.indexOf(u8, result, "Subject:")) |idx| {
        const line_end = std.mem.indexOfPos(u8, result, idx, "\n") orelse result.len;
        const subject = std.mem.trim(u8, result[idx + 8..line_end], " \t");
        try cert_info.put("subject", Value{ .String = try interp.allocator.dupe(u8, subject) });
    }
    
    // Store raw output
    try cert_info.put("raw", Value{ .String = result });
    
    return Value{ .Dict = cert_info };
}

// ============================================================================
// Metadata Extraction
// ============================================================================

// extract_metadata(file_path) - Extract metadata from files
pub fn builtin_extract_metadata(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .Dict = std.StringHashMap(Value).init(interp.allocator) };
    }
    
    const file_path = args[0].String;
    
    // Use exiftool if available
    const script = try std.fmt.allocPrint(interp.allocator,
        \\exiftool '{s}' 2>/dev/null | head -30
    , .{file_path});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch {
        // Fallback to file command
        const fallback_script = try std.fmt.allocPrint(interp.allocator,
            \\file '{s}' 2>/dev/null
        , .{file_path});
        defer interp.allocator.free(fallback_script);
        
        const fallback_result = executeShellCommand(interp.allocator, fallback_script) catch 
            return Value{ .Dict = std.StringHashMap(Value).init(interp.allocator) };
        
        var meta = std.StringHashMap(Value).init(interp.allocator);
        try meta.put("type", Value{ .String = fallback_result });
        return Value{ .Dict = meta };
    };
    
    var metadata = std.StringHashMap(Value).init(interp.allocator);
    
    var it = std.mem.splitScalar(u8, result, '\n');
    var count: usize = 0;
    while (it.next()) |line| {
        if (count >= 20) break; // Limit output
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        
        if (std.mem.indexOf(u8, trimmed, ":")) |colon_pos| {
            const key = std.mem.trim(u8, trimmed[0..colon_pos], " \t");
            const value = std.mem.trim(u8, trimmed[colon_pos + 1..], " \t");
            
            const key_copy = try interp.allocator.dupe(u8, key);
            const value_copy = try interp.allocator.dupe(u8, value);
            try metadata.put(key_copy, Value{ .String = value_copy });
            count += 1;
        }
    }
    
    return Value{ .Dict = metadata };
}

// ============================================================================
// Network Reconnaissance
// ============================================================================

// reverse_dns(ip) - Reverse DNS lookup
pub fn builtin_reverse_dns(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len == 0 or args[0] != .String) {
        return Value{ .String = "" };
    }
    
    const ip = args[0].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\dig +short -x {s} 2>/dev/null | head -1
    , .{ip});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .String = "lookup failed" };
    
    const trimmed = std.mem.trim(u8, result, " \t\r\n.");
    if (trimmed.len == 0) {
        return Value{ .String = "no PTR record" };
    }
    
    return Value{ .String = try interp.allocator.dupe(u8, trimmed) };
}

// shodan_search(query, api_key) - Shodan search (requires API key)
pub fn builtin_shodan_search(interp: *Interpreter, args: []Value) InterpreterError!Value {
    if (args.len < 2 or args[0] != .String or args[1] != .String) {
        return Value{ .String = "Missing query or API key" };
    }
    
    const query = args[0].String;
    const api_key = args[1].String;
    
    const script = try std.fmt.allocPrint(interp.allocator,
        \\curl -s "https://api.shodan.io/shodan/host/search?key={s}&query={s}" 2>/dev/null
    , .{api_key, query});
    defer interp.allocator.free(script);
    
    const result = executeShellCommand(interp.allocator, script) catch 
        return Value{ .String = "Shodan API request failed" };
    
    return Value{ .String = result };
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
